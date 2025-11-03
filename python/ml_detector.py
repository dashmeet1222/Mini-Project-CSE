#!/usr/bin/env python3
"""
Machine Learning Threat Detection Module
Implements various ML algorithms for network intrusion detection
"""

import numpy as np
import pandas as pd
import json
import pickle
from datetime import datetime
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.svm import OneClassSVM
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
import joblib

class MLThreatDetector:
    def __init__(self):
        self.models = {}
        self.scalers = {}
        self.encoders = {}
        self.feature_columns = []
        self.is_trained = False
        
    def prepare_features(self, flow_data):
        """Prepare features for ML training/prediction"""
        if not flow_data:
            return np.array([]), []
        
        df = pd.DataFrame(flow_data)
        
        # Select numerical features
        numerical_features = [
            'duration', 'packet_count', 'total_bytes', 'avg_packet_size',
            'std_packet_size', 'packet_rate', 'byte_rate', 'avg_inter_arrival',
            'std_inter_arrival', 'syn_count', 'ack_count', 'fin_count', 'rst_count'
        ]
        
        # Select categorical features
        categorical_features = ['protocol', 'is_well_known_port', 'is_ephemeral_port']
        
        # Prepare feature matrix
        feature_matrix = []
        feature_names = []
        
        # Add numerical features
        for feature in numerical_features:
            if feature in df.columns:
                values = pd.to_numeric(df[feature], errors='coerce').fillna(0)
                feature_matrix.append(values.values)
                feature_names.append(feature)
        
        # Add categorical features
        for feature in categorical_features:
            if feature in df.columns:
                if feature == 'protocol':
                    # One-hot encode protocols
                    protocols = df[feature].fillna('Unknown')
                    unique_protocols = ['TCP', 'UDP', 'HTTP', 'HTTPS', 'DNS', 'SSH']
                    for protocol in unique_protocols:
                        feature_matrix.append((protocols == protocol).astype(int).values)
                        feature_names.append(f'protocol_{protocol}')
                else:
                    # Boolean features
                    values = df[feature].fillna(False).astype(int)
                    feature_matrix.append(values.values)
                    feature_names.append(feature)
        
        if feature_matrix:
            X = np.column_stack(feature_matrix)
            self.feature_columns = feature_names
            return X, feature_names
        else:
            return np.array([]), []
    
    def _initialize_pretrained_models(self):
        """Initialize pre-trained models for immediate threat detection"""
        print("Initializing pre-trained ML models...")
        
        # Generate training data and train models immediately
        training_data = self.generate_synthetic_training_data(2000)
        
        # Prepare features and labels
        X, feature_names = self.prepare_features(training_data)
        if X.size == 0:
            print("Warning: Could not initialize models")
            return
        
        labels = [item.get('label', 'normal') for item in training_data]
        
        # Encode labels
        self.encoders['label'] = LabelEncoder()
        y = self.encoders['label'].fit_transform(labels)
        
        # Scale features
        self.scalers['features'] = StandardScaler()
        X_scaled = self.scalers['features'].fit_transform(X)
        
        # Train models with full dataset
        print("Training Random Forest classifier...")
        self.models['random_forest'] = RandomForestClassifier(
            n_estimators=100, random_state=42, n_jobs=-1
        )
        self.models['random_forest'].fit(X_scaled, y)
        
        # Train Isolation Forest for anomaly detection
        print("Training Isolation Forest...")
        self.models['isolation_forest'] = IsolationForest(
            contamination=0.1, random_state=42, n_jobs=-1
        )
        normal_mask = y == self.encoders['label'].transform(['normal'])[0]
        self.models['isolation_forest'].fit(X_scaled[normal_mask])
        
        # Train One-Class SVM
        print("Training One-Class SVM...")
        self.models['one_class_svm'] = OneClassSVM(gamma='scale', nu=0.1)
        self.models['one_class_svm'].fit(X_scaled[normal_mask])
        
        self.is_trained = True
        print("✓ Pre-trained models ready for real-time threat detection!")
    
    def generate_synthetic_training_data(self, n_samples=1000):
        """Generate synthetic training data for demonstration"""
        np.random.seed(42)
        
        # Generate normal traffic patterns
        normal_data = []
        for i in range(int(n_samples * 0.8)):
            flow = {
                'duration': np.random.exponential(10),
                'packet_count': np.random.poisson(50),
                'total_bytes': np.random.normal(5000, 2000),
                'avg_packet_size': np.random.normal(1000, 300),
                'std_packet_size': np.random.normal(200, 50),
                'packet_rate': np.random.normal(10, 3),
                'byte_rate': np.random.normal(1000, 300),
                'avg_inter_arrival': np.random.exponential(0.1),
                'std_inter_arrival': np.random.exponential(0.05),
                'syn_count': np.random.poisson(2),
                'ack_count': np.random.poisson(10),
                'fin_count': np.random.poisson(1),
                'rst_count': np.random.poisson(0.1),
                'protocol': np.random.choice(['TCP', 'UDP', 'HTTP', 'HTTPS']),
                'is_well_known_port': np.random.choice([True, False], p=[0.7, 0.3]),
                'is_ephemeral_port': np.random.choice([True, False], p=[0.3, 0.7]),
                'label': 'normal'
            }
            normal_data.append(flow)
        
        # Generate attack patterns
        attack_data = []
        attack_types = ['ddos', 'port_scan', 'malware', 'brute_force']
        
        for i in range(int(n_samples * 0.2)):
            attack_type = np.random.choice(attack_types)
            
            if attack_type == 'ddos':
                flow = {
                    'duration': np.random.exponential(1),
                    'packet_count': np.random.poisson(200),
                    'total_bytes': np.random.normal(20000, 5000),
                    'avg_packet_size': np.random.normal(100, 30),
                    'std_packet_size': np.random.normal(50, 20),
                    'packet_rate': np.random.normal(100, 30),
                    'byte_rate': np.random.normal(10000, 3000),
                    'avg_inter_arrival': np.random.exponential(0.01),
                    'std_inter_arrival': np.random.exponential(0.005),
                    'syn_count': np.random.poisson(50),
                    'ack_count': np.random.poisson(5),
                    'fin_count': np.random.poisson(0),
                    'rst_count': np.random.poisson(10),
                    'protocol': 'TCP',
                    'is_well_known_port': True,
                    'is_ephemeral_port': False,
                    'label': 'ddos'
                }
            elif attack_type == 'port_scan':
                flow = {
                    'duration': np.random.exponential(30),
                    'packet_count': np.random.poisson(5),
                    'total_bytes': np.random.normal(500, 100),
                    'avg_packet_size': np.random.normal(100, 20),
                    'std_packet_size': np.random.normal(20, 5),
                    'packet_rate': np.random.normal(1, 0.3),
                    'byte_rate': np.random.normal(100, 30),
                    'avg_inter_arrival': np.random.exponential(1),
                    'std_inter_arrival': np.random.exponential(0.5),
                    'syn_count': np.random.poisson(1),
                    'ack_count': np.random.poisson(0),
                    'fin_count': np.random.poisson(0),
                    'rst_count': np.random.poisson(1),
                    'protocol': 'TCP',
                    'is_well_known_port': True,
                    'is_ephemeral_port': False,
                    'label': 'port_scan'
                }
            else:
                # Generic attack pattern
                flow = {
                    'duration': np.random.exponential(5),
                    'packet_count': np.random.poisson(30),
                    'total_bytes': np.random.normal(3000, 1000),
                    'avg_packet_size': np.random.normal(500, 200),
                    'std_packet_size': np.random.normal(100, 30),
                    'packet_rate': np.random.normal(20, 10),
                    'byte_rate': np.random.normal(2000, 500),
                    'avg_inter_arrival': np.random.exponential(0.05),
                    'std_inter_arrival': np.random.exponential(0.02),
                    'syn_count': np.random.poisson(5),
                    'ack_count': np.random.poisson(15),
                    'fin_count': np.random.poisson(2),
                    'rst_count': np.random.poisson(1),
                    'protocol': np.random.choice(['TCP', 'UDP']),
                    'is_well_known_port': np.random.choice([True, False]),
                    'is_ephemeral_port': np.random.choice([True, False]),
                    'label': attack_type
                }
            
            attack_data.append(flow)
        
        return normal_data + attack_data
    
    def train_models(self, training_data=None):
        """Train ML models for threat detection"""
        if training_data is None:
            print("Generating synthetic training data...")
            training_data = self.generate_synthetic_training_data()
        
        # Prepare features
        X, feature_names = self.prepare_features(training_data)
        if X.size == 0:
            print("Error: No features extracted from training data")
            return False
        
        # Prepare labels
        labels = [item.get('label', 'normal') for item in training_data]
        
        # Encode labels
        self.encoders['label'] = LabelEncoder()
        y = self.encoders['label'].fit_transform(labels)
        
        # Scale features
        self.scalers['features'] = StandardScaler()
        X_scaled = self.scalers['features'].fit_transform(X)
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X_scaled, y, test_size=0.2, random_state=42, stratify=y
        )
        
        print(f"Training with {len(X_train)} samples, {len(feature_names)} features")
        
        # Train Random Forest (supervised)
        print("Training Random Forest classifier...")
        self.models['random_forest'] = RandomForestClassifier(
            n_estimators=100, random_state=42, n_jobs=-1
        )
        self.models['random_forest'].fit(X_train, y_train)
        
        # Evaluate Random Forest
        rf_pred = self.models['random_forest'].predict(X_test)
        print("Random Forest Classification Report:")
        print(classification_report(y_test, rf_pred, 
                                  target_names=self.encoders['label'].classes_))
        
        # Train Isolation Forest (unsupervised anomaly detection)
        print("Training Isolation Forest...")
        self.models['isolation_forest'] = IsolationForest(
            contamination=0.1, random_state=42, n_jobs=-1
        )
        # Train only on normal traffic for anomaly detection
        normal_mask = y_train == self.encoders['label'].transform(['normal'])[0]
        self.models['isolation_forest'].fit(X_train[normal_mask])
        
        # Train One-Class SVM
        print("Training One-Class SVM...")
        self.models['one_class_svm'] = OneClassSVM(gamma='scale', nu=0.1)
        self.models['one_class_svm'].fit(X_train[normal_mask])
        
        self.is_trained = True
        print("Model training completed successfully!")
        return True
    
    def predict_threats(self, flow_data):
        """Predict threats using trained models"""
        if not self.is_trained:
            print("Models not trained. Please train models first.")
            return []
        
        if not flow_data:
            return []
        
        # Prepare features
        X, _ = self.prepare_features(flow_data)
        if X.size == 0:
            return []
        
        # Scale features
        X_scaled = self.scalers['features'].transform(X)
        
        predictions = []
        
        for i, flow in enumerate(flow_data):
            sample = X_scaled[i:i+1]
            
            # Random Forest prediction
            rf_pred = self.models['random_forest'].predict(sample)[0]
            rf_proba = self.models['random_forest'].predict_proba(sample)[0]
            rf_confidence = max(rf_proba) * 100
            
            # Isolation Forest prediction
            if_pred = self.models['isolation_forest'].predict(sample)[0]
            if_anomaly = if_pred == -1
            
            # One-Class SVM prediction
            svm_pred = self.models['one_class_svm'].predict(sample)[0]
            svm_anomaly = svm_pred == -1
            
            # Combine predictions
            predicted_label = self.encoders['label'].inverse_transform([rf_pred])[0]
            is_threat = predicted_label != 'normal' or if_anomaly or svm_anomaly
            
            if is_threat:
                # Determine threat type and severity
                if predicted_label == 'ddos':
                    threat_type = 'DDoS Attack'
                    severity = 'Critical'
                elif predicted_label == 'port_scan':
                    threat_type = 'Port Scan'
                    severity = 'High'
                elif predicted_label == 'brute_force':
                    threat_type = 'Brute Force'
                    severity = 'High'
                elif if_anomaly or svm_anomaly:
                    threat_type = 'Anomalous Behavior'
                    severity = 'Medium'
                else:
                    threat_type = predicted_label.replace('_', ' ').title()
                    severity = 'Medium'
                
                prediction = {
                    'flow_id': flow.get('flow_id', f'flow_{i}'),
                    'src_ip': flow.get('src_ip', 'unknown'),
                    'dest_ip': flow.get('dest_ip', 'unknown'),
                    'threat_type': threat_type,
                    'severity': severity,
                    'confidence': int(rf_confidence),
                    'ml_prediction': predicted_label,
                    'anomaly_detected': if_anomaly or svm_anomaly,
                    'timestamp': flow.get('timestamp', datetime.now().isoformat()),
                    'model_version': '1.0'
                }
                
                predictions.append(prediction)
        
        return predictions
    
    def save_models(self, filepath='models/ml_detector_models.pkl'):
        """Save trained models to file"""
        if not self.is_trained:
            print("No trained models to save")
            return False
        
        try:
            model_data = {
                'models': self.models,
                'scalers': self.scalers,
                'encoders': self.encoders,
                'feature_columns': self.feature_columns,
                'is_trained': self.is_trained,
                'save_timestamp': datetime.now().isoformat()
            }
            
            joblib.dump(model_data, filepath)
            print(f"Models saved to {filepath}")
            return True
        except Exception as e:
            print(f"Error saving models: {e}")
            return False
    
    def load_models(self, filepath='models/ml_detector_models.pkl'):
        """Load trained models from file"""
        try:
            model_data = joblib.load(filepath)
            
            self.models = model_data['models']
            self.scalers = model_data['scalers']
            self.encoders = model_data['encoders']
            self.feature_columns = model_data['feature_columns']
            self.is_trained = model_data['is_trained']
            
            print(f"Models loaded from {filepath}")
            return True
        except Exception as e:
            print(f"Error loading models: {e}")
            return False
    
    def get_model_info(self):
        """Get information about trained models"""
        if not self.is_trained:
            return {"status": "not_trained"}
        
        info = {
            "status": "trained",
            "models": list(self.models.keys()),
            "feature_count": len(self.feature_columns),
            "features": self.feature_columns
        }
        
        # Add Random Forest specific info
        if 'random_forest' in self.models:
            rf = self.models['random_forest']
            info['random_forest'] = {
                'n_estimators': rf.n_estimators,
                'feature_importances': dict(zip(self.feature_columns, 
                                               rf.feature_importances_.tolist()))
            }
        
        return info

def main():
    """Main function for testing"""
    detector = MLThreatDetector()
    
    print("Training ML models...")
    success = detector.train_models()
    
    if success:
        print("\nModel information:")
        info = detector.get_model_info()
        print(json.dumps(info, indent=2))
        
        # Save models
        detector.save_models()
        
        # Test prediction with sample data
        sample_flow = [{
            'duration': 0.5,
            'packet_count': 200,
            'total_bytes': 20000,
            'avg_packet_size': 100,
            'std_packet_size': 50,
            'packet_rate': 400,
            'byte_rate': 40000,
            'avg_inter_arrival': 0.0025,
            'std_inter_arrival': 0.001,
            'syn_count': 50,
            'ack_count': 5,
            'fin_count': 0,
            'rst_count': 10,
            'protocol': 'TCP',
            'is_well_known_port': True,
            'is_ephemeral_port': False,
            'src_ip': '192.168.1.100',
            'dest_ip': '10.0.0.1'
        }]
        
        threats = detector.predict_threats(sample_flow)
        print(f"\nDetected {len(threats)} threats:")
        for threat in threats:
            print(json.dumps(threat, indent=2))

if __name__ == "__main__":
    main()