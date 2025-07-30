# 🛡️ IDS MLOps - Système de Détection d'Intrusions

Un système complet de détection d'intrusions réseau utilisant des techniques de Machine Learning avec un pipeline MLOps automatisé.

## 🎯 Aperçu du Projet

Ce projet implémente un système de détection d'intrusions (IDS) intelligent capable de :
- **Détecter automatiquement** les attaques réseau en temps réel
- **Classifier** le trafic normal vs malveillant avec >99% de précision
- **Identifier** différents types d'attaques (DoS, Probe, R2L, U2R)
- **Monitorer** et améliorer continuellement les performances

### 📊 Performances Actuelles
- **Precision** : 99.91%
- **Recall** : 99.72% (seulement 33 attaques manquées sur 11,726)
- **F1-Score** : 99.82%
- **Latence** : <1ms par prédiction

## 🏗️ Architecture

```
├── data/                    # Données du projet
│   ├── raw/                 # Datasets originaux (NSL-KDD)
│   └── processed/           # Données prétraitées
├── src/                     # Code source principal
│   ├── data/
│   │   └── preprocessing.py # Pipeline de nettoyage des données
│   ├── models/              # Scripts ML
│   └── utils/               # Utilitaires
├── notebooks/               # Jupyter notebooks
│   ├── 01_data_exploration.ipynb
│   └── 02_preprocessing_baseline.ipynb
├── models/                  # Modèles sauvegardés
├── mlruns/                  # MLflow tracking
└── requirements.txt         # Dépendances Python
```

## 🚀 Installation et Utilisation

### Prérequis
- Python 3.8+
- pip ou conda

### 1. Cloner le projet
```bash
git clone <votre-repo>
cd ids-mlops-project
```

### 2. Créer l'environnement virtuel
```bash
python -m venv venv

# Windows
venv\Scripts\activate

# Mac/Linux  
source venv/bin/activate
```

### 3. Installer les dépendances
```bash
pip install -r requirements.txt
```

### 4. Télécharger les données
Téléchargez le dataset NSL-KDD depuis [UNB](https://www.unb.ca/cic/datasets/nsl.html) :
- `KDDTrain+.txt` → `data/raw/`
- `KDDTest+.txt` → `data/raw/`

### 5. Reproduire les résultats
```bash
# Lancer MLflow UI (dans un terminal séparé)
mlflow ui

# Exécuter les notebooks dans l'ordre
jupyter notebook
# 1. notebooks/01_data_exploration.ipynb
# 2. notebooks/02_preprocessing_baseline.ipynb
```

## 📈 Pipeline ML

### 1. Exploration des Données (EDA)
- **125,973 échantillons** d'entraînement
- **23 types d'attaques** différents
- **41 features** numériques et catégorielles
- Identification des **features discriminantes**

### 2. Preprocessing
- **Nettoyage** : Suppression des features constantes et creuses
- **Encoding** : One-hot encoding pour les variables catégorielles
- **Transformation** : Log-transformation pour gérer les outliers
- **Scaling** : StandardScaler pour les features numériques

### 3. Modélisation
- **Algorithme** : Random Forest avec class weights
- **Optimisation** : Maximisation du recall (détection d'attaques)
- **Validation** : Train/test split avec stratification

### 4. MLOps
- **Tracking** : MLflow pour l'expérimentation
- **Registry** : Versioning des modèles
- **Reproductibilité** : Seeds fixés et environment sauvegardé

## 🔧 Utilisation du Modèle

### Chargement depuis MLflow
```python
import mlflow.sklearn

# Charger le modèle de production
model_uri = "models:/IDS_RandomForest_Production/latest"
model = mlflow.sklearn.load_model(model_uri)

# Prédiction
prediction = model.predict(X_new)
```

### Preprocessing des nouvelles données
```python
from src.data.preprocessing import clean_dataset, prepare_for_ml

# Nettoyer les nouvelles données
df_clean, features = clean_dataset(new_data, target_binary=True)

# Préparer pour la prédiction
X_new = df_clean[features]
```

## 📊 Résultats Détaillés

### Performance par Type d'Attaque
| Catégorie | Échantillons | Taux Détection |
|-----------|--------------|----------------|
| Normal    | 13,469       | 99.88%         |
| DoS       | 9,234        | 99.85%         |
| Probe     | 2,289        | 99.43%         |
| R2L       | 198          | 97.47%         |
| U2R       | 11           | 90.91%         |

### Features les Plus Importantes
1. **dst_bytes_log** (16.69%) - Bytes de destination
2. **src_bytes_log** (15.75%) - Bytes source  
3. **flag_SF** (13.47%) - Status de connexion
4. **same_srv_rate** (7.97%) - Taux même service
5. **dst_host_srv_count** (6.13%) - Compteur connexions

## 🛠️ Technologies Utilisées

- **Python 3.8+** - Langage principal
- **Scikit-learn** - Machine Learning
- **MLflow** - Tracking et registry
- **Pandas/NumPy** - Manipulation des données
- **Matplotlib/Seaborn** - Visualisations
- **Jupyter** - Développement interactif

## 📁 Structure des Données

### Dataset NSL-KDD
- **Source** : Canadian Institute for Cybersecurity
- **Type** : Trafic réseau étiqueté
- **Features** : 41 caractéristiques par connexion
- **Classes** : Normal + 4 types d'attaques

### Features Principales
- **Connexion** : durée, protocole, service, flag
- **Contenu** : bytes échangés, tentatives de login
- **Trafic** : compteurs, taux d'erreur
- **Hôte** : statistiques par destination

## 🔮 Évolutions Futures

### Phase 1 - API de Production
- [ ] API FastAPI pour serving en temps réel
- [ ] Documentation Swagger automatique
- [ ] Tests unitaires et d'intégration

### Phase 2 - Monitoring Avancé
- [ ] Détection de dérive des données
- [ ] Alertes automatiques Slack/Email
- [ ] Dashboard Grafana temps réel

### Phase 3 - Déploiement Cloud
- [ ] Containerisation Docker
- [ ] Orchestration Kubernetes
- [ ] CI/CD avec GitHub Actions

## 🤝 Contribution

1. **Fork** le projet
2. **Créez** une branche feature (`git checkout -b feature/improvement`)
3. **Committez** vos changements (`git commit -m 'Add improvement'`)
4. **Push** vers la branche (`git push origin feature/improvement`)
5. **Ouvrez** une Pull Request

## 📝 License

Ce projet est sous licence MIT. Voir le fichier `LICENSE` pour plus de détails.

## 🙏 Remerciements

- **NSL-KDD Dataset** - University of New Brunswick
- **MLflow** - Databricks pour l'excellent outil MLOps
- **Scikit-learn** - Pour les algorithmes ML robustes

## 📞 Contact

**Yassine HANDANE**
- 📧 Email : y.handane@gmail.com
- 💼 LinkedIn : [Yassine HANDANE](https://linkedin.com/in/yassine-handane)
- 🐙 GitHub : [YsnHdn](https://github.com/YsnHdn)

---

⭐ **Si ce projet vous aide, n'hésitez pas à lui donner une étoile !**