"""
Interface to VulDeePecker project

读取 graph.pkl 文件，把 func_key 和 commits 提取出来，func_key 的集合即为 A。遍历所有 entities 文件，如果其 func_key 在 A 中，写入到 gadget.json 文件中。

gadget.json 每行是一个 json:
    {
        "func_key": "",
        "commit": "",
        "contents": "",
        "vul": 0
    }

"""
import sys
import os
import pandas
from clean_gadget import clean_gadget
from vectorize_gadget import GadgetVectorizer
from blstm import BLSTM
import json

import logging
from pathlib import Path
import json
import argparse
import time

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# log file
LOG_PATH = BASE_DIR + "/logs"
Path(LOG_PATH).mkdir(parents=True, exist_ok=True)

now_time = time.strftime("%Y-%m-%d_%H-%M", time.localtime())
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s %(levelname)s %(filename)s line: %(lineno)s - %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S',
                    filename=LOG_PATH + '/' + now_time + '_vuldeepecker.log')
logger = logging.getLogger(__name__)


# args
parser = argparse.ArgumentParser(description='Test for argparse')
parser.add_argument('--save_path', help='save_path', type=str, default= '')
parser.add_argument('--gadget_file', help='gadget_file', type=str, default='/data/baselines/vdpython/big_vul_2.0_gadgets.json')

args = parser.parse_args()
logger.info("args %s", args)

SAVE_PATH = args.save_path

"""
Parses gadget file to find individual gadgets
Yields each gadget as list of strings, where each element is code line
Has to ignore first line of each gadget, which starts as integer+space
At the end of each code gadget is binary value
    This indicates whether or not there is vulnerability in that gadget
"""
def parse_file(filename):
    if filename.endswith(".json"):
        with open(filename, "r", encoding="utf8") as file:
            for line in file:
                if line.strip() == "":
                    continue
                obj = json.loads(line)
                gadget = obj['contents'].split("\n")
                gadget_val = obj['vul']
                yield clean_gadget(gadget), gadget_val
    else:
        with open(filename, "r", encoding="utf8") as file:
            gadget = []
            gadget_val = 0
            for line in file:
                stripped = line.strip()
                if not stripped:
                    continue
                if "-" * 33 in line and gadget:
                    yield clean_gadget(gadget), gadget_val
                    gadget = []
                elif stripped.split()[0].isdigit():
                    if gadget:
                        # Code line could start with number (somehow)
                        if stripped.isdigit():
                            gadget_val = int(stripped)
                        else:
                            gadget.append(stripped)
                else:
                    gadget.append(stripped)

"""
Uses gadget file parser to get gadgets and vulnerability indicators
Assuming all gadgets can fit in memory, build list of gadget dictionaries
    Dictionary contains gadgets and vulnerability indicator
    Add each gadget to GadgetVectorizer
Train GadgetVectorizer model, prepare for vectorization
Loop again through list of gadgets
    Vectorize each gadget and put vector into new list
Convert list of dictionaries to dataframe when all gadgets are processed
"""
def get_vectors_df(filename, vector_length=100):
    logger.info("get_vectors_df")
    gadgets = []
    count = 0
    vectorizer = GadgetVectorizer(vector_length)
    for gadget, val in parse_file(filename):
        count += 1
        logger.info("Collecting gadgets... {}".format(count) )
        vectorizer.add_gadget(gadget)
        row = {"gadget" : gadget, "val" : val}
        gadgets.append(row)
    logger.info('Found {} forward slices and {} backward slices'
          .format(vectorizer.forward_slices, vectorizer.backward_slices))
    # print()
    logger.info("Training model...")
    vectorizer.train_model()
    # print()
    vectors = []
    count = 0
    for gadget in gadgets:
        count += 1
        logger.info("Processing gadgets... {}".format(count))
        vector = vectorizer.vectorize(gadget["gadget"])
        row = {"vector" : vector, "val" : gadget["val"]}
        vectors.append(row)
    # print()
    df = pandas.DataFrame(vectors)
    return df
            
"""
Gets filename, either loads vector DataFrame if exists or creates it if not
Instantiate neural network, pass data to it, train, test, print accuracy
"""
def main():
    # if len(sys.argv) != 2:
    #     print("Usage: python vuldeepecker.py [filename]")
    #     exit()
    filename = args.gadget_file
    parse_file(filename)
    base = os.path.splitext(os.path.basename(filename))[0]
    vector_filename = SAVE_PATH + "/" + base + "_gadget_vectors.pkl"
    vector_length = 50
    if os.path.exists(vector_filename):
        df = pandas.read_pickle(vector_filename)
    else:
        df = get_vectors_df(filename, vector_length)
        df.to_pickle(vector_filename)
    blstm = BLSTM(SAVE_PATH, df,name=base)
    blstm.train()
    blstm.test()

if __name__ == "__main__":
    main()