#!/usr/bin/env python3
__author__ = 'Matthew Schwartz'

import os
from collections import Counter

import numpy as np
from scipy.stats import entropy
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.metrics import accuracy_score, f1_score, classification_report
from sklearn.model_selection import train_test_split
import skops.io as sio


def preprocess_files(directory):
    data = []
    for filename in os.listdir(directory):
        file_path = os.path.join(directory, filename)
        with open(file_path, 'rb') as file:
            byte_sequence = file.read()
            data.append(byte_sequence)
    return data


def byte_entropy(byte_sequence):
    # Convert the raw bytes into a list of integers
    byte_sequence = [b for b in byte_sequence]
    byte_sequence = np.array(byte_sequence, dtype=np.uint8)
    byte_counts = np.bincount(byte_sequence)
    probabilities = byte_counts / len(byte_sequence)
    entropy = -np.sum([prob * np.log2(prob)
                       for prob in probabilities if prob > 0])
    return entropy


def byte_frequency_distribution(byte_sequence):
    counter = Counter(byte_sequence)
    distribution = [counter[i] for i in range(256)]
    return np.array(distribution) / len(byte_sequence)


def byte_n_grams(byte_sequence, n):
    # Convert the raw bytes into a list of integers
    byte_sequence = [b for b in byte_sequence]
    n_grams = zip(*[byte_sequence[i:] for i in range(n)])
    return [''.join([chr(b) for b in gram]) for gram in n_grams]


malware_dir = 'malware_book'
benign_dir = 'benign_book'
malware_data = preprocess_files(malware_dir)
benign_data = preprocess_files(benign_dir)

X_entropy = [byte_entropy(seq) for seq in malware_data + benign_data]
X_frequency = [byte_frequency_distribution(
    seq) for seq in malware_data + benign_data]
X_n_grams = [' '.join(byte_n_grams(seq, 3))
             for seq in malware_data + benign_data]

vectorizer = CountVectorizer()
X_n_grams_vectorized = vectorizer.fit_transform(X_n_grams).toarray()

X_combined = np.hstack((np.array(X_entropy).reshape(-1, 1),
                        np.array(X_frequency), X_n_grams_vectorized))
y = np.concatenate((np.ones(len(malware_data)), np.zeros(len(benign_data))))

X_train, X_test, y_train, y_test = train_test_split(
    X_combined, y, test_size=0.2, random_state=42)

clf = RandomForestClassifier(n_estimators=100, random_state=42)
clf.fit(X_train, y_train)

y_pred = clf.predict(X_test)
print("Accuracy:", accuracy_score(y_test, y_pred))
print("F1 Score:", f1_score(y_test, y_pred))
print(classification_report(y_test, y_pred))

# Save the trained model and the vectorizer
sio.dump(clf, 'malware_classification_model-byte-level.skops')
sio.dump(vectorizer, 'vectorizer-byte-level.skops')
