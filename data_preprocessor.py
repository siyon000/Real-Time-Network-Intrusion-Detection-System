import pandas as pd
import numpy as np

def preprocess_network_data(input_file):
    """
    Preprocess network traffic CSV for machine learning models
    
    Args:
        input_file (str or pandas.DataFrame): Path to CSV or DataFrame to preprocess
    
    Returns:
        pandas.DataFrame: Preprocessed data ready for model prediction
    """
    # If input is a file path, read the CSV
    if isinstance(input_file, str):
        df = pd.read_csv(input_file)
    else:
        df = input_file.copy()
    
    # List of required features for the model
    REQUIRED_FEATURES = [
        "Flow Duration", "Tot Fwd Pkts", "Tot Bwd Pkts", "TotLen Fwd Pkts", "TotLen Bwd Pkts",
        "Fwd Pkt Len Max", "Fwd Pkt Len Min", "Fwd Pkt Len Mean", "Fwd Pkt Len Std", 
        "Bwd Pkt Len Max", "Bwd Pkt Len Min", "Bwd Pkt Len Mean", "Bwd Pkt Len Std", 
        "Flow Byts/s", "Flow Pkts/s", "Flow IAT Mean", "Flow IAT Std", "Flow IAT Max", 
        "Flow IAT Min", "Fwd IAT Tot", "Fwd IAT Mean", "Fwd IAT Std", "Fwd IAT Max", 
        "Fwd IAT Min", "Bwd IAT Tot", "Bwd IAT Mean", "Bwd IAT Std", "Bwd IAT Max", 
        "Bwd IAT Min", "Fwd PSH Flags", "Bwd PSH Flags", "Fwd URG Flags", "Bwd URG Flags", 
        "Fwd Header Len", "Bwd Header Len", "Fwd Pkts/s", "Bwd Pkts/s", "Pkt Len Min", 
        "Pkt Len Max", "Pkt Len Mean", "Pkt Len Std", "Pkt Len Var", "FIN Flag Cnt", 
        "SYN Flag Cnt", "RST Flag Cnt", "PSH Flag Cnt", "ACK Flag Cnt", "URG Flag Cnt", 
        "CWE Flag Count", "ECE Flag Cnt", "Down/Up Ratio", "Pkt Size Avg", "Fwd Seg Size Avg", 
        "Bwd Seg Size Avg", "Fwd Byts/b Avg", "Fwd Pkts/b Avg", "Fwd Blk Rate Avg", 
        "Bwd Byts/b Avg", "Bwd Pkts/b Avg", "Bwd Blk Rate Avg", "Subflow Fwd Pkts", 
        "Subflow Fwd Byts", "Subflow Bwd Pkts", "Subflow Bwd Byts", "Init Fwd Win Byts", 
        "Init Bwd Win Byts", "Fwd Act Data Pkts", "Fwd Seg Size Min", "Active Mean", 
        "Active Std", "Active Max", "Active Min", "Idle Mean", "Idle Std", "Idle Max", "Idle Min"
    ]
    
    # Remove unnecessary columns
    columns_to_drop = [col for col in df.columns if col not in REQUIRED_FEATURES + ['Timestamp', 'Src IP', 'Dst IP', 'Prediction']]
    df = df.drop(columns=columns_to_drop, errors='ignore')
    
    # Add missing columns with zero values if not present
    for feature in REQUIRED_FEATURES:
        if feature not in df.columns:
            df[feature] = 0.0
    
    # Ensure correct order of columns
    df = df[REQUIRED_FEATURES]
    
    # Convert to float to ensure numeric type
    df = df.astype(float)
    
    return df

def validate_data(df):
    """
    Validate preprocessed dataframe
    
    Args:
        df (pandas.DataFrame): Preprocessed dataframe
    
    Returns:
        bool: Whether data is valid for prediction
    """
    REQUIRED_FEATURES = [
        "Flow Duration", "Tot Fwd Pkts", "Tot Bwd Pkts", "TotLen Fwd Pkts", "TotLen Bwd Pkts",
        # ... (rest of the features from previous list)
    ]
    
    # Check for missing features
    missing_features = [feat for feat in REQUIRED_FEATURES if feat not in df.columns]
    if missing_features:
        print(f"Missing features: {missing_features}")
        return False
    
    # Check for non-numeric data
    try:
        df[REQUIRED_FEATURES] = df[REQUIRED_FEATURES].astype(float)
    except ValueError:
        print("Non-numeric data found in required features")
        return False
    
    return True