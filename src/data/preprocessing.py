# ===== ENRICHISSEMENT DE preprocessing.py =====

import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler, LabelEncoder
import warnings
warnings.filterwarnings('ignore')

def load_nsl_kdd(file_path):
    """Charge un fichier NSL-KDD avec les noms de colonnes"""
    columns = ['duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes',
               'land', 'wrong_fragment', 'urgent', 'hot', 'num_failed_logins',
               'logged_in', 'num_compromised', 'root_shell', 'su_attempted', 'num_root',
               'num_file_creations', 'num_shells', 'num_access_files', 'num_outbound_cmds',
               'is_host_login', 'is_guest_login', 'count', 'srv_count', 'serror_rate',
               'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate', 'same_srv_rate',
               'diff_srv_rate', 'srv_diff_host_rate', 'dst_host_count',
               'dst_host_srv_count', 'dst_host_same_srv_rate', 'dst_host_diff_srv_rate',
               'dst_host_same_src_port_rate', 'dst_host_srv_diff_host_rate',
               'dst_host_serror_rate', 'dst_host_srv_serror_rate', 'dst_host_rerror_rate',
               'dst_host_srv_rerror_rate', 'attack', 'level']
    
    df = pd.read_csv(file_path, names=columns)
    return df

def clean_dataset(df, target_binary=True):
    """
    Nettoie le dataset selon les conclusions de l'EDA
    
    Args:
        df: DataFrame brut
        target_binary: Si True, convertit en problème binaire (Normal vs Attaque)
    
    Returns:
        df_clean: DataFrame nettoyé
        feature_names: Liste des features finales
    """
    print("🔧 DÉBUT DU PREPROCESSING...")
    df_clean = df.copy()
    
    # 1. SUPPRESSION FEATURES PROBLÉMATIQUES
    print("\n1️⃣ Suppression des features problématiques...")
    
    # Features constantes
    constant_features = ['num_outbound_cmds']
    
    # Features très creuses (>95% de zéros)
    sparse_features = [
        'land', 'urgent', 'num_shells', 'is_host_login',
        'num_failed_logins', 'root_shell', 'su_attempted',
        'num_file_creations', 'num_access_files'
    ]
    
    features_to_drop = constant_features + sparse_features + ['level']  # level pas utile
    
    print(f"   Suppression de {len(features_to_drop)} features: {features_to_drop}")
    df_clean = df_clean.drop(columns=features_to_drop, errors='ignore')
    
    # 2. GESTION DU TARGET
    print("\n2️⃣ Gestion du target...")
    if target_binary:
        df_clean['target'] = (df_clean['attack'] != 'normal').astype(int)
        print("   Target binaire créé: 0=Normal, 1=Attaque")
    else:
        # Mapping vers catégories principales
        attack_mapping = {
            'normal': 'normal',
            'neptune': 'DoS', 'smurf': 'DoS', 'pod': 'DoS', 'teardrop': 'DoS', 
            'land': 'DoS', 'back': 'DoS',
            'satan': 'Probe', 'ipsweep': 'Probe', 'portsweep': 'Probe', 'nmap': 'Probe',
            'warezclient': 'R2L', 'warezmaster': 'R2L', 'ftpwrite': 'R2L', 
            'guess_passwd': 'R2L', 'imap': 'R2L', 'multihop': 'R2L', 'phf': 'R2L', 'spy': 'R2L',
            'buffer_overflow': 'U2R', 'loadmodule': 'U2R', 'perl': 'U2R', 'rootkit': 'U2R'
        }
        df_clean['target'] = df_clean['attack'].map(attack_mapping).fillna('unknown')
        print("   Target catégoriel créé avec 5 classes")
    
    # Supprimer la colonne attack originale
    df_clean = df_clean.drop('attack', axis=1)
    
    # 3. GESTION FEATURES NUMÉRIQUES
    print("\n3️⃣ Preprocessing features numériques...")
    numeric_features = df_clean.select_dtypes(include=[np.number]).columns.tolist()
    numeric_features.remove('target')  # Exclure le target
    
    # Log transformation pour features avec outliers
    log_features = ['src_bytes', 'dst_bytes', 'duration']
    for feature in log_features:
        if feature in df_clean.columns:
            # +1 pour éviter log(0)
            df_clean[f'{feature}_log'] = np.log1p(df_clean[feature])
            print(f"   Log transformation appliquée à {feature}")
    
    # 4. GESTION FEATURES CATÉGORIELLES
    print("\n4️⃣ Encoding features catégorielles...")
    
    # Protocol type (3 valeurs) - One hot encoding
    if 'protocol_type' in df_clean.columns:
        protocol_dummies = pd.get_dummies(df_clean['protocol_type'], prefix='protocol')
        df_clean = pd.concat([df_clean, protocol_dummies], axis=1)
        df_clean.drop('protocol_type', axis=1, inplace=True)
        print("   Protocol_type encodé (one-hot)")
    
    # Flag (11 valeurs) - One hot encoding
    if 'flag' in df_clean.columns:
        flag_dummies = pd.get_dummies(df_clean['flag'], prefix='flag')
        df_clean = pd.concat([df_clean, flag_dummies], axis=1)
        df_clean.drop('flag', axis=1, inplace=True)
        print("   Flag encodé (one-hot)")
    
    # Service - Simplification puis encoding
    if 'service' in df_clean.columns:
        # Regrouper les services rares
        service_counts = df_clean['service'].value_counts()
        frequent_services = service_counts[service_counts > 100].index.tolist()
        
        df_clean['service_grouped'] = df_clean['service'].apply(
            lambda x: x if x in frequent_services else 'other_service'
        )
        
        service_dummies = pd.get_dummies(df_clean['service_grouped'], prefix='service')
        df_clean = pd.concat([df_clean, service_dummies], axis=1)
        df_clean.drop(['service', 'service_grouped'], axis=1, inplace=True)
        print(f"   Service regroupé et encodé ({len(frequent_services)} services fréquents)")
    
    # 5. FEATURE SELECTION FINAL
    print("\n5️⃣ Sélection features finales...")
    
    # Garder seulement les features les plus importantes
    important_numeric = [
        'src_bytes_log', 'dst_bytes_log', 'duration_log',
        'logged_in', 'count', 'srv_count', 'same_srv_rate',
        'dst_host_count', 'dst_host_srv_count'
    ]
    
    # Features finales = importantes + encodées + target
    feature_cols = [col for col in df_clean.columns 
                   if col.startswith('protocol_') or col.startswith('flag_') or 
                      col.startswith('service_') or col in important_numeric]
    
    final_columns = feature_cols + ['target']
    df_clean = df_clean[final_columns]
    
    print(f"   Features finales sélectionnées: {len(feature_cols)}")
    print(f"   Shape final: {df_clean.shape}")
    
    feature_names = [col for col in df_clean.columns if col != 'target']
    
    print("\n✅ PREPROCESSING TERMINÉ !")
    return df_clean, feature_names

def prepare_for_ml(df_clean, test_size=0.2, random_state=42):
    """
    Prépare les données pour l'entraînement ML
    
    Args:
        df_clean: DataFrame nettoyé
        test_size: Taille du set de test
        random_state: Seed pour reproductibilité
    
    Returns:
        X_train, X_test, y_train, y_test, scaler
    """
    from sklearn.model_selection import train_test_split
    from sklearn.preprocessing import StandardScaler
    
    print("📊 PRÉPARATION POUR ML...")
    
    # Séparation features / target
    X = df_clean.drop('target', axis=1)
    y = df_clean['target']
    
    # Train/test split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=test_size, random_state=random_state, stratify=y
    )
    
    # Scaling des features numériques seulement
    numeric_columns = X_train.select_dtypes(include=[np.number]).columns
    scaler = StandardScaler()
    
    X_train_scaled = X_train.copy()
    X_test_scaled = X_test.copy()
    
    X_train_scaled[numeric_columns] = scaler.fit_transform(X_train[numeric_columns])
    X_test_scaled[numeric_columns] = scaler.transform(X_test[numeric_columns])
    
    print(f"   Train set: {X_train_scaled.shape}")
    print(f"   Test set: {X_test_scaled.shape}")
    print(f"   Distribution target train: {y_train.value_counts().values}")
    
    return X_train_scaled, X_test_scaled, y_train, y_test, scaler