#!/usr/bin/env python3
__author__ = 'Matthew Schwartz'

import argparse
from collections import Counter

import numpy as np
import skops.io as sio
from scipy.stats import entropy
from sklearn.feature_extraction.text import CountVectorizer

def preprocess_file(file_path):
    with open(file_path, 'rb') as file:
        byte_sequence = file.read()
    
    entropy_val = byte_entropy(byte_sequence)
    frequency_dist = byte_frequency_distribution(byte_sequence)
    n_grams = ' '.join(byte_n_grams(byte_sequence, 3))
    
    X_n_grams_vectorized = vectorizer.transform([n_grams]).toarray()
    
    features = np.hstack((np.array([[entropy_val]]).reshape(-1, 1),
                          np.array(frequency_dist).reshape(1, -1),
                          X_n_grams_vectorized))
    
    return features


def byte_entropy(byte_sequence):
    byte_sequence = np.frombuffer(byte_sequence, dtype=np.uint8)
    byte_counts = np.bincount(byte_sequence)
    probabilities = byte_counts / len(byte_sequence)
    entropy_val = -np.sum([prob * np.log2(prob) for prob in probabilities if prob > 0])
    return entropy_val


def byte_frequency_distribution(byte_sequence):
    counter = Counter(byte_sequence)
    distribution = [counter[i] for i in range(256)]
    return np.array(distribution) / len(byte_sequence)


def byte_n_grams(byte_sequence, n):
    byte_sequence = np.frombuffer(byte_sequence, dtype=np.uint8)
    n_grams = zip(*[byte_sequence[i:] for i in range(n)])
    return [''.join([chr(b) for b in gram]) for gram in n_grams]


# Load the vectorizer and classifier
vectorizer = sio.load('vectorizer-byte-level.skops', trusted=True)
clf =sio.load('malware_classification_model-byte-level.skops', trusted=True)

# Parse command line arguments
parser = argparse.ArgumentParser(description='Evaluate a file using the byte-level model')
parser.add_argument('file', type=str, help='File to evaluate')
args = parser.parse_args()

# Preprocess the file
features = preprocess_file(args.file)

# Make prediction using the loaded classifier
prediction = clf.predict(features)

# Print predicted probabilities
y_pred_proba = clf.predict_proba(features)

# Print the prediction
if prediction == 0:
    print(f"The file '{args.file}' is classified as benign. Predicted probabilities:", y_pred_proba)
else:
    print(f"The file '{args.file}' is classified as malicious. Predicted probabilities:", y_pred_proba)

