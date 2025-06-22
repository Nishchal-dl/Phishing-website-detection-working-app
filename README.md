# Phishing Website Detection System

A Flask-based web application that detects phishing websites using machine learning models. The system analyzes various features of a given URL and its content to determine if it's likely a phishing attempt.
This is a part of the final project demo for AAI-500 

## Features

- **URL Analysis**: Examines URL structure and components for suspicious patterns
- **Content Inspection**: Analyzes HTML/JavaScript content for malicious indicators
- **Multiple Models**: Uses three different ML models for prediction

## Project Structure

```
phishing-website-detection/
├── src/                      # Source code
│   ├── templates/            # HTML templates
│   ├── models/               # Trained model files to be saved when running the notebook
│   ├── utils/                # Utility modules
│   ├── app.py                # Main Flask application
│   ├── config.py             # Configuration settings
├── requirements.txt          # Python dependencies
└── README.md                # Project documentation
```

## Setup Instructions

2. **Create and activate a virtual environment**
   ```bash
   # Windows
   python -m venv venv
   venv\Scripts\activate.bat
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Train the models**
   
   Make sure to run the notebook and save the models under the `src/models` folder as a .joblib file.

   The application expects models with names
   random_forest.joblib
   xgboost.joblib
   logistic_regression.joblib

5. **Run the application**
   ```bash
   python app.py
   ```
   The application will be available at `http://localhost:5000`

## Usage

1. Open your web browser and navigate to `http://localhost:5000`
2. Enter the URL you want to analyze in the input field
3. Click the "Analyze" button
4. View the results, including:
   - Prediction from each model (Random Forest, XGBoost, Logistic Regression)
   - Extracted features and their values

## Features Extracted

The system analyzes 30 different features, including:

- URL-based features (length, special characters, etc.)
- Domain information (age, registration length)
- HTML/JavaScript content (iframes, popups, forms)
- Security features (HTTPS, SSL certificate)

## Limitations

- This would not work for sites which are bot protected 

## Team

- Ritesh Jain
- Rajneesh Kumar
- Nishchal P

