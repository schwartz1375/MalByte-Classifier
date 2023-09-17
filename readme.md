# MalByte-Classifier

This purpose of this POC was to develop a script to perform byte-level analysis on a set of binary files, 
specifically executable files, for the purpose of malware classification. The script extracts three different 
types of features from the binary files: byte frequency distribution, byte entropy, and byte n-grams. These 
features are used to train a machine learning model to classify the files as either benign or malicious. 
 
* Byte Frequency Distribution: The script calculates the frequency distribution of bytes in the binary files. 
It generates a 256-dimensional feature vector representing the occurrence count of each byte value (0-255) in 
the file. This feature captures the overall structure and composition of the binary files, which can be useful 
for distinguishing between benign and malicious files.
 
* Byte Entropy: Entropy is a measure of randomness or disorder in a dataset. In this script, byte entropy is 
calculated for each file, providing an insight into the complexity and potential obfuscation techniques used 
within the file. Higher entropy values may indicate the presence of encrypted or compressed sections in the file, 
which can be a characteristic of malware.

* Byte N-Grams: N-grams are contiguous sequences of 'n' items from a given sample. In this script, byte n-grams 
are generated from the binary files. The n-grams capture local patterns and structures within the files that can 
be indicative of malware or benign software. By considering n-grams instead of individual bytes, the script can 
capture more complex relationships between bytes in the files.

## Testing Data
Book data (https://www.malwaredatascience.com/code-and-data, specifically ch8/data)
```
% python3 ./byte-level.py 
Accuracy: 0.968421052631579
F1 Score: 0.9461077844311377
              precision    recall  f1-score   support

         0.0       0.97      0.98      0.98       200
         1.0       0.96      0.93      0.95        85

    accuracy                           0.97       285
   macro avg       0.97      0.96      0.96       285
weighted avg       0.97      0.97      0.97       285
```

Execution with a larger data set:
```
% python3 ./byte-level.py 
Accuracy: 0.805
F1 Score: 0.7979274611398964
              precision    recall  f1-score   support

         0.0       0.79      0.84      0.81       201
         1.0       0.82      0.77      0.80       199

    accuracy                           0.81       400
   macro avg       0.81      0.80      0.80       400
weighted avg       0.81      0.81      0.80       400
```

Example for Multiple Files
```
for file in ~/Desktop/samples/*; do python3 ./evaluate_byte-level.py "$file" >> results.txt; done
```