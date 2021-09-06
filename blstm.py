from __future__ import print_function

import warnings

from keras.utils import to_categorical
from sklearn import metrics
from sklearn.metrics import confusion_matrix
from sklearn.utils import compute_class_weight

warnings.filterwarnings("ignore")

import numpy as np

from keras.models import Sequential
from keras.layers import Dense, Dropout, LSTM, Bidirectional, LeakyReLU
from keras.optimizers import Adamax

from sklearn.model_selection import train_test_split
import logging

"""
Bidirectional LSTM neural network
Structure consists of two hidden layers and a BLSTM layer
Parameters, as from the VulDeePecker paper:
    Nodes: 300
    Dropout: 0.5
    Optimizer: Adamax
    Batch size: 64
    Epochs: 4
"""
class BLSTM:
    def __init__(self, save_path, data, name="", batch_size=64):
        vectors = np.stack(data.iloc[:, 0].values)
        labels = data.iloc[:, 1].values
        print(data.head())
        logging.info("vectors.shape: {}".format(vectors.shape))
        logging.info("labels.shape: {}".format(labels.shape))
        positive_idxs = np.where(labels == 1)[0]
        negative_idxs = np.where(labels == 0)[0]
        logging.info("positive_idxs.shape: {}".format(positive_idxs.shape))
        logging.info("negative_idxs.shape: {}".format(negative_idxs.shape))
        undersampled_negative_idxs = np.random.choice(negative_idxs, len(positive_idxs), replace=False)
        resampled_idxs = np.concatenate([positive_idxs, undersampled_negative_idxs])
        logging.info("resampled_idxs.shape: {}".format(resampled_idxs.shape))

        X_train, X_test, y_train, y_test = train_test_split(vectors[resampled_idxs, ], labels[resampled_idxs],
                                                            test_size=0.2, stratify=labels[resampled_idxs])
        self.save_path = save_path
        self.X_train = X_train
        self.X_test = X_test
        self.y_train = to_categorical(y_train)
        self.y_test = to_categorical(y_test)
        self.name = name
        self.batch_size = batch_size
        self.class_weight = compute_class_weight(class_weight='balanced', classes=[0, 1], y=labels)
        model = Sequential()
        model.add(Bidirectional(LSTM(300), input_shape=(vectors.shape[1], vectors.shape[2])))
        model.add(Dense(300))
        model.add(LeakyReLU())
        model.add(Dropout(0.5))
        model.add(Dense(300))
        model.add(LeakyReLU())
        model.add(Dropout(0.5))
        model.add(Dense(2, activation='softmax'))
        # Lower learning rate to prevent divergence
        adamax = Adamax(lr=0.002)
        model.compile(adamax, 'categorical_crossentropy', metrics=['accuracy'])
        self.model = model

    """
    Trains model based on training data
    """
    def train(self):
        self.model.fit(self.X_train, self.y_train, batch_size=self.batch_size, epochs=4, class_weight=self.class_weight)
        self.model.save_weights(self.save_path + "/" + self.name + "_model.h5")

    """
    Tests accuracy of model based on test data
    Loads weights from file if no weights are attached to model object
    """
    def test(self):
        self.model.load_weights(self.save_path + "/" + self.name + "_model.h5")
        values = self.model.evaluate(self.X_test, self.y_test, batch_size=self.batch_size)
        logging.info("Accuracy is... {}".format( values[1]) )
        predictions = (self.model.predict(self.X_test, batch_size=self.batch_size)).round()

        tn, fp, fn, tp = confusion_matrix(np.argmax(self.y_test, axis=1), np.argmax(predictions, axis=1)).ravel()
        logging.info('False positive rate is... {}'.format( fp / (fp + tn)))
        logging.info('False negative rate is... {}'.format( fn / (fn + tp)))
        recall = tp / (tp + fn)
        logging.info('Recall is... {}'.format( recall))
        precision = tp / (tp + fp)
        logging.info('Precision is... {}'.format(precision))
        logging.info('F1 score is... {}'.format( (2 * precision * recall) / (precision + recall)) )