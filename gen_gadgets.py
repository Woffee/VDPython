"""


@Time    : 9/6/21
@Author  : Wenbo
"""
try:
    import cPickle as pickle
except:
    import pickle

import os
import numpy as np
import pandas as pd
import time
# from datetime import datetime
# import networkx as nx
import logging
from pathlib import Path
import json
import argparse


BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# log file
LOG_PATH = BASE_DIR + "/logs"
Path(LOG_PATH).mkdir(parents=True, exist_ok=True)

now_time = time.strftime("%Y-%m-%d_%H-%M", time.localtime())
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s %(levelname)s %(filename)s line: %(lineno)s - %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S',
                    filename=LOG_PATH + '/' + now_time + '_gen_gadgets.log')
logger = logging.getLogger(__name__)


# args
parser = argparse.ArgumentParser(description='Test for argparse')
parser.add_argument('--functions_path', help='functions_path', type=str, default='')
parser.add_argument('--save_path', help='save_path', type=str, default= '')
parser.add_argument('--graph_file', help='graph_file', type=str, default='')
parser.add_argument('--commits_file', help='commits_file', type=str, default='')

args = parser.parse_args()
logger.info("args %s", args)


def findAllFile(base, full=True):
    for root, ds, fs in os.walk(base):
        for f in fs:
            if full:
                yield os.path.join(root, f)
            else:
                yield f

def read_commits_file(commits_file):
    df = pd.read_csv(commits_file)
    commits_vul = list(df['vul'])
    commits_non_vul = list(df['non_vul'])
    logger.info("commits_vul: {}, non_vul: {}".format(len(commits_vul), len(commits_non_vul)))
    return commits_vul, commits_non_vul

def get_commits(df, repo_name, cve_id):
    df2 = df[(df["repo_name"] == repo_name) & (df["cve_id"] == cve_id)]
    vuls = list(df2['vul'])
    non_vuls = list(df2['non_vul'])
    return vuls, non_vuls

def main():
    # to_file_graphs = EMBEDDING_PATH + "/graphs_{}_hop.pkl".format(HOP)
    # /dlvp/data/function2vec5/graphs_2_hop.pkl

    graph_file = args.graph_file
    commits_file = args.commits_file
    if not os.path.exists(graph_file):
        logger.info("graph file not exists: {}".format(graph_file))
        exit()
    if not os.path.exists(commits_file):
        logger.info("graph file not exists: {}".format(graph_file))
        exit()

    # read commits
    # df = pd.read_csv(commits_file)

    # read graphs
    with open(graph_file, 'rb') as fh:
        graphs = pickle.load(fh)
    func_key_vul = {}
    vul_cnt = 0
    non_vul_cnt = 0
    for g in graphs:
        func_key = g['func_key']
        func_key_vul[func_key] = int(g['vul'])
        if func_key_vul[func_key] > 0:
            vul_cnt += 1
        else:
            non_vul_cnt += 1
        # func_key_list.append(func_key)
    logger.info("len of func_key_list: {}, vuls: {}, non_vuls: {}".format(len(func_key_vul.keys()), vul_cnt, non_vul_cnt))

    # read entities
    ii = 0
    to_file = args.save_path + "/big_vul_2.0_gadgets.json"
    for file in findAllFile(args.functions_path):
        if not file.endswith(".json"):
            continue
        logger.info("now {}, file: {}".format(ii, file))
        ii += 1

        cnt = 0
        # each line is a json string
        with open(file) as f:
            for line in f:
                if line.strip() == "":
                    continue
                obj = json.loads(line)
                if obj['func_key'] in func_key_vul.keys():
                    vul = func_key_vul[ obj['func_key'] ]
                    # if obj['commit'] in commits_vul:
                    #     vul = 1
                    # elif obj['commit'] in commits_non_vul:
                    #     vul = 0
                    # else:
                    #     continue
                    with open(to_file, "a") as fw:
                        fw.write(json.dumps({
                            "func_key": obj['func_key'],
                            "contents": obj['contents'],
                            "vul": vul,
                            "commit": obj['commit']
                        }) + "\n")
                    cnt += 1
        #
        # if file.find("jh_entities.json") > -1:
        #     # each line is a json string
        #     with open(file) as f:
        #         for line in f:
        #             if line.strip() == "":
        #                 continue
        #             obj = json.loads(line)
        #             if obj['func_key'] in func_key_list:
        #                 if obj['commit'] in commits_vul:
        #                     vul = 1
        #                 elif obj['commit'] in commits_non_vul:
        #                     vul = 0
        #                 else:
        #                     continue
        #                 with open(to_file, "a") as fw:
        #                     fw.write(json.dumps({
        #                         "func_key": obj['func_key'],
        #                         "contents": obj['contents'],
        #                         "vul": vul,
        #                         "commit": obj['commit']
        #                     }) + "\n")
        #                 cnt += 1
        #
        # else:
        #     # the whole file is a json string
        #     with open(file) as f:
        #         obj = json.loads(f.read())
        #     for k, v in obj.items():
        #         if k in func_key_list:
        #             if v['commit'] in commits_vul:
        #                 vul = 1
        #             elif v['commit'] in commits_non_vul:
        #                 vul = 0
        #             else:
        #                 continue
        #             with open(to_file, "a") as fw:
        #                 fw.write(json.dumps({
        #                     "func_key": k,
        #                     "contents": v['contents'],
        #                     "vul": vul,
        #                     "commit": v['commit']
        #                 }) + "\n")
        #             cnt += 1
        logger.info("functions: {}".format(cnt))


if __name__ == '__main__':
    try:
        main()
    except Exception as exception:
        logger.exception(exception)
        raise

    logger.info("done")