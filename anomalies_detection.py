import os
import time
import pandas as pd
import numpy as np
from scapy.all import sniff, IP, TCP, UDP
from sklearn.preprocessing import StandardScaler
from tensorflow.keras.models import Sequential, load_model
from tensorflow.keras.layers import Dense, Dropout
from tensorflow.keras.callbacks import EarlyStopping
import joblib
from collections import defaultdict
from datetime import datetime

# Configuration
TRAINING_DURATION = 86400  # 1 hour is 86400 seconds
TEST_WINDOW = 60  # 60 for continuous analysis
MODEL_PATH = 'flow_autoencoder.h5'
SCALER_PATH = 'flow_scaler.pkl'
THRESHOLD_PATH = 'anomaly_threshold.pkl'
TRAINING_DATA_PATH = 'training_flows.csv'
REPORT_PATH = 'anomaly_report.txt'


active_flows = defaultdict(lambda: {
    'start_time': None,
    'last_seen': None,
    'packet_count': 0,
    'total_bytes': 0,
    'ports': set()
})


def collect_flows(duration, output_file):
    start_time = time.time()
    
    def process_packet(packet):
        if IP not in packet:
            return
        flow_key = (
            packet[IP].src, packet[IP].dst,
            packet[IP].proto,
            packet.sport if TCP in packet or UDP in packet else 0,
            packet.dport if TCP in packet or UDP in packet else 0
        )
        
        now = time.time()
        flow = active_flows[flow_key]
        
        if flow['start_time'] is None:
            flow['start_time'] = now
        flow['last_seen'] = now
        flow['packet_count'] += 1
        flow['total_bytes'] += len(packet)
        if TCP in packet or UDP in packet:
            flow['ports'].update([packet.sport, packet.dport])
        
    sniff(timeout=duration, prn=process_packet, store=0)
    
    expired = []
    for key, flow in active_flows.items():
        if (time.time() - flow['last_seen']) > 60:  # time out if idle for 60 seconds
            expired.append((key, flow))
    
    flows_data = []
    for (src, dst, proto, sport, dport), flow in expired:
        flows_data.append([
            src, dst, proto, sport, dport,
            flow['packet_count'],
            flow['total_bytes'],
            flow['last_seen'] - flow['start_time'],
            len(flow['ports'])
        ])
        del active_flows[(src, dst, proto, sport, dport)]
    
    df = pd.DataFrame(flows_data, columns=[
        'src_ip', 'dst_ip', 'proto', 'sport', 'dport',
        'packet_count', 'total_bytes', 'duration', 'unique_ports'
    ])
    
    df.to_csv(output_file, mode='a', header=not os.path.exists(output_file), index=False)

#Feature Engineering 
def preprocess_flow_data(df, fit=False):
    # Frequency encoding for IPs
    df['src_ip_freq'] = df.groupby('src_ip')['src_ip'].transform('count')
    df['dst_ip_freq'] = df.groupby('dst_ip')['dst_ip'].transform('count')

    features = [
        'proto', 'packet_count', 'total_bytes', 'duration',
        'unique_ports', 'src_ip_freq', 'dst_ip_freq'
    ]
    
    if fit:
        scaler = StandardScaler()
        scaled = scaler.fit_transform(df[features])
        joblib.dump(scaler, SCALER_PATH)
    else:
        scaler = joblib.load(SCALER_PATH)
        scaled = scaler.transform(df[features])
    
    return scaled

#Autoencoder Model 
def build_autoencoder(input_dim):
    model = Sequential([
        Dense(32, activation='relu', input_shape=(input_dim,)),
        Dropout(0.2),
        Dense(16, activation='relu'),
        Dense(32, activation='relu'),
        Dense(input_dim, activation='linear')
    ])
    model.compile(optimizer='adam', loss='mse')
    return model

def train_model(data):
    model = build_autoencoder(data.shape[1])
    early_stop = EarlyStopping(monitor='val_loss', patience=5)
    model.fit(data, data, epochs=50, batch_size=32,
              validation_split=0.2, callbacks=[early_stop], verbose=1)
    model.save(MODEL_PATH)
    
    #Здесь установлен порог
    reconstructions = model.predict(data)
    mse = np.mean(np.power(data - reconstructions, 2), axis=1)
    threshold = np.percentile(mse, 95)
    joblib.dump(threshold, THRESHOLD_PATH)
    
    return model, threshold


def detect_anomalies(model, threshold, data):
    reconstructions = model.predict(data)
    mse = np.mean(np.power(data - reconstructions, 2), axis=1)
    return mse > threshold


def continuous_monitoring():
    model = load_model(MODEL_PATH)
    scaler = joblib.load(SCALER_PATH)
    threshold = joblib.load(THRESHOLD_PATH)
    
    while True:
        print(f"\n[+] Collecting test window ({TEST_WINDOW}s)...")
        collect_flows(TEST_WINDOW, 'test_flows.csv')
        
        test_df = pd.read_csv('test_flows.csv')
        if test_df.empty:
            continue
            
        test_data = preprocess_flow_data(test_df)
        anomalies = detect_anomalies(model, threshold, test_data)
        
        with open(REPORT_PATH, 'a') as f:
            for idx, row in test_df[anomalies].iterrows():
                report = (
                    f"{datetime.now()} - ANOMALY: {row['src_ip']} -> {row['dst_ip']} "
                    f"Proto={row['proto']}, Packets={row['packet_count']}, "
                    f"Bytes={row['total_bytes']}, Duration={row['duration']:.2f}s\n"
                )
                print(report)
                f.write(report)


def main():
    if not os.path.exists(MODEL_PATH):
        print("Collecting network data to train the model. Duration of the collection is set to take ", TRAINING_DURATION, " seconds. To change the duration, set the TRAINING_SURATION variable to a different value. ")
        collect_flows(TRAINING_DURATION, TRAINING_DATA_PATH)
        train_df = pd.read_csv(TRAINING_DATA_PATH)
        print("Training model on the collected data")
        train_data = preprocess_flow_data(train_df, fit=True)
        model, threshold = train_model(train_data)
        print(f"[!] Training complete. Threshold: {threshold:.4f}")
    
    print("[!] Starting continuous monitoring...")
    continuous_monitoring()

if __name__ == "__main__":
    main()
