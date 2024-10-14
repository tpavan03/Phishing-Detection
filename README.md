# Phishing Detection Using Machine Learning

This project aims to detect phishing websites using machine learning models and various interpretability techniques to explain predictions.

## Approach
* **Exploratory Data Analysis (EDA):**
  * Checked for null values.
  * Checked for duplicate values.
  * Checked for missing values.
  * Compared feature distribution with the labels.
  * Compared the features with one another with different graphs.
  * Generated conclusions based on the plots generated and explained our dataset and the relationships within attributes with respect to target class labels.

* **Phase 2:**
  * Decision Tree Classifier created then optimised with metric values extracted by Grid Search.
  * Random Forest Classifier performed and optimised the same as Decision Tree.
  * Neural Networks created with 1 input layer, 5 hidden layers and 1 output layer with Sigmoid activation function.
  * All models evaluated on Accuracy, Precision, Recall and F1 Score.
    
* **Neural Network Models:**
  * Creating Embeddings:
    * Previously URLs in unsupported format
    * Converted URLs into Embedding Vectors so that they are compatible with the models.
    * Embeddings generated using
      * BERT_CLS(768)
      * SBERT(384)
      * USE(512)
      * FastText(300)
      * RoBERTa(768)
      * AlBERT(768)

  * Neural Networks:
    * Performed with only URLs and both URL and numerical features.
    * Compared both the approaches with each other.
    * Models used:
      * Feed Forward Neural Networks(FFNN)
      * Recurrent Neural Networks(RNN)
      * Long-short term memory(LSTM)
* **Explainability:** 
