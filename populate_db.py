import pandas as pd
from sqlalchemy import create_engine, text
from tqdm import tqdm
import os

# Database connection settings 
DATABASE_URL = 'postgresql+psycopg2:///intrusion_db'

# Dataset file path 
CSV_PATH = "/home/aayushmaan/IntrusionDetection/ML-Based-Network-Intrusion-Detection-System-/KDDTrain+.txt"

def populate():
    print("Connecting to database...")
    engine = create_engine(DATABASE_URL)
    
    with engine.connect() as conn:
        print("Cleaning up old data...")
        conn.execute(text("TRUNCATE TABLE connections CASCADE;"))
        conn.execute(text("TRUNCATE TABLE destination CASCADE;"))
        conn.execute(text("TRUNCATE TABLE protocol_types CASCADE;"))
        conn.execute(text("TRUNCATE TABLE services CASCADE;"))
        conn.execute(text("TRUNCATE TABLE flags CASCADE;"))
        conn.execute(text("TRUNCATE TABLE attack_types CASCADE;"))
        conn.execute(text("TRUNCATE TABLE attack_categories CASCADE;"))
        conn.commit()

    # 1. Load Dataset
    print("Loading dataset...")
    FULL_COLUMN_NAMES = [
        'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes',
        'land', 'wrong_fragment', 'urgent', 'hot', 'num_failed_logins', 'logged_in',
        'num_compromised', 'root_shell', 'su_attempted', 'num_root', 'num_file_creations',
        'num_shells', 'num_access_files', 'num_outbound_cmds', 'is_host_login',
        'is_guest_login', 'count', 'srv_count', 'serror_rate', 'srv_serror_rate',
        'rerror_rate', 'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate',
        'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count',
        'dst_host_same_srv_rate', 'dst_host_diff_srv_rate',
        'dst_host_same_src_port_rate', 'dst_host_srv_diff_host_rate',
        'dst_host_serror_rate', 'dst_host_srv_serror_rate',
        'dst_host_rerror_rate', 'dst_host_srv_rerror_rate', 'label', 'difficulty_level'
    ]
    
    # Columns needed for lookups and destination table
    COLS_TO_LOAD = [
        'duration', 'src_bytes', 'land', 'logged_in', 'count', 'srv_count', 'serror_rate', 
        'rerror_rate', 'same_srv_rate', 'diff_srv_rate', 'dst_host_count', 'dst_host_srv_count', 
        'difficulty_level', 'protocol_type', 'service', 'flag', 'label',
        'dst_bytes', 'dst_host_same_srv_rate', 'dst_host_diff_srv_rate', 'dst_host_serror_rate'
    ]
    
    df = pd.read_csv(CSV_PATH, header=None, names=FULL_COLUMN_NAMES, usecols=COLS_TO_LOAD)

    # 2. Populate Lookup Tables
    print("Populating lookup tables...")
    pd.DataFrame({'protocol_name': df['protocol_type'].unique()}).to_sql('protocol_types', engine, if_exists='append', index=False)
    pd.DataFrame({'service_name': df['service'].unique()}).to_sql('services', engine, if_exists='append', index=False)
    pd.DataFrame({'flag_value': df['flag'].unique()}).to_sql('flags', engine, if_exists='append', index=False)
    
    pd.DataFrame({'category_name': ['DoS', 'Probe', 'R2L', 'U2R', 'Normal']}).to_sql('attack_categories', engine, if_exists='append', index=False)
    
    cat_map = pd.read_sql("SELECT category_id, category_name FROM attack_categories", engine)
    cat_dict = dict(zip(cat_map['category_name'], cat_map['category_id']))
    
    label_to_cat = {
        'normal': 'Normal',
        'neptune': 'DoS', 'back': 'DoS', 'land': 'DoS', 'pod': 'DoS', 'smurf': 'DoS', 'teardrop': 'DoS', 'mailbomb': 'DoS', 'apache2': 'DoS', 'processtable': 'DoS', 'udpstorm': 'DoS',
        'ipsweep': 'Probe', 'nmap': 'Probe', 'portsweep': 'Probe', 'satan': 'Probe', 'mscan': 'Probe', 'saint': 'Probe',
        'ftp_write': 'R2L', 'guess_passwd': 'R2L', 'imap': 'R2L', 'multihop': 'R2L', 'phf': 'R2L', 'spy': 'R2L', 'warezclient': 'R2L', 'warezmaster': 'R2L', 'sendmail': 'R2L', 'named': 'R2L', 'snmpgetattack': 'R2L', 'snmpguess': 'R2L', 'xlock': 'R2L', 'xsnoop': 'R2L', 'worm': 'R2L',
        'buffer_overflow': 'U2R', 'loadmodule': 'U2R', 'perl': 'U2R', 'rootkit': 'U2R', 'sqlattack': 'U2R', 'xterm': 'U2R', 'ps': 'U2R'
    }
    
    unique_labels = df['label'].unique()
    attack_types = [{'attack_name': label, 'category_id': cat_dict[label_to_cat.get(label, 'Normal')]} for label in unique_labels]
    pd.DataFrame(attack_types).to_sql('attack_types', engine, if_exists='append', index=False)

    # 3. Populate Destination Table
    print("Populating destination table...")
    DEST_METRICS = ['dst_bytes', 'dst_host_count', 'dst_host_srv_count', 'dst_host_same_srv_rate', 'dst_host_diff_srv_rate', 'dst_host_serror_rate']
    df_dest = df[DEST_METRICS].drop_duplicates().reset_index(drop=True)
    df_dest.to_sql('destination', engine, if_exists='append', index=False)
    
    # Load destination IDs for mapping
    # Note: Using the unique constraint for matching
    dest_map_df = pd.read_sql("SELECT destination_id, " + ", ".join(DEST_METRICS) + " FROM destination", engine)
    
    # Efficiently merge to get destination_id
    print("Mapping destination IDs...")
    df = df.merge(dest_map_df, on=DEST_METRICS, how='left')

    # 4. Map other IDs
    print("Mapping lookup IDs...")
    protocol_dict = dict(zip(pd.read_sql("SELECT protocol_name, protocol_id FROM protocol_types", engine).iloc[:,0], pd.read_sql("SELECT protocol_name, protocol_id FROM protocol_types", engine).iloc[:,1]))
    service_dict = dict(zip(pd.read_sql("SELECT service_name, service_id FROM services", engine).iloc[:,0], pd.read_sql("SELECT service_name, service_id FROM services", engine).iloc[:,1]))
    flag_dict = dict(zip(pd.read_sql("SELECT flag_value, flag_id FROM flags", engine).iloc[:,0], pd.read_sql("SELECT flag_value, flag_id FROM flags", engine).iloc[:,1]))
    attack_dict = dict(zip(pd.read_sql("SELECT attack_name, attack_id FROM attack_types", engine).iloc[:,0], pd.read_sql("SELECT attack_name, attack_id FROM attack_types", engine).iloc[:,1]))

    df['protocol_id'] = df['protocol_type'].map(protocol_dict)
    df['service_id'] = df['service'].map(service_dict)
    df['flag_id'] = df['flag'].map(flag_dict)
    df['attack_id'] = df['label'].map(attack_dict)
    df['land'] = df['land'].astype(int).astype(bool)
    df['logged_in'] = df['logged_in'].astype(int).astype(bool)

    # 5. Insert Connections
    # Columns matching actual DB schema (fact table)
    # destination_id is now part of the insert
    FINAL_COLS = [
        'duration', 'src_bytes', 'dst_bytes', 'land', 'logged_in', 'count', 'srv_count', 'serror_rate', 
        'rerror_rate', 'same_srv_rate', 'dst_host_count', 'dst_host_srv_count', 'difficulty_level',
        'protocol_id', 'service_id', 'flag_id', 'attack_id', 'destination_id'
    ]
    
    df_clean = df[FINAL_COLS]
    
    chunksize = 10000
    print(f"Inserting {len(df_clean)} rows into connections table...")
    for i in tqdm(range(0, len(df_clean), chunksize)):
        chunk = df_clean[i:i+chunksize]
        chunk.to_sql('connections', engine, if_exists='append', index=False)

    print("Population complete!")

if __name__ == "__main__":
    populate()
