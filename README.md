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
  * Decision Tree Classifier created then optimised with metric values.
  * Random Forest Classifier performed and optimised the same as Decision Tree.
  * Neural Networks created with 1 input layer, 5 hidden layers with Relu activation function and 1 output layer with Sigmoid activation function.
  * All models evaluated on Accuracy, Precision, Recall and F1 Score.
    
* **Embedding for Phishing URLs:**
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
  * Assigns scores based on the contribution of the feature on the model.
  * Score is determined by approximating the integral of the gradient of the output with respect to its input.
  * Negative scores indicate that the features affect the model negatively.
  * Faithfullness Check:
    * Removing top few attributes and comparing new accuracy results with the old ones.
  * Robustness Check:
    * Introduction of noise to the model to check its impact on the model.
  * SHAP:
    *  Game theoretic approach to explain the output of any machine learning model.
    *  How features with high importance impacts the prediction of models.
    *  How models perform without this features. 
