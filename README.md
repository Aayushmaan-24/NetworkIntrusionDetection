<div align="center">
  <img src="https://stock.adobe.com/search?k=cyber+security+logo" alt="Logo">
  <h1>ML-Based Network Intrusion Detection System 🛡️</h1>
  <p><strong>Classify and defend against network intrusions with Machine Learning and PostgreSQL</strong></p>

  <!-- Badges -->
  <p>
    <img src="https://img.shields.io/badge/Python-3.11+-blue.svg?style=flat-square&logo=python&logoColor=white" alt="Python">
    <img src="https://img.shields.io/badge/PostgreSQL-15.0+-336791.svg?style=flat-square&logo=postgresql&logoColor=white" alt="PostgreSQL">
    <img src="https://img.shields.io/badge/FastAPI-0.100+-009688.svg?style=flat-square&logo=fastapi&logoColor=white" alt="FastAPI">
    <img src="https://img.shields.io/badge/Scikit--Learn-1.2+-F7931E.svg?style=flat-square&logo=scikit-learn&logoColor=white" alt="Scikit-Learn">
    <img src="https://img.shields.io/badge/License-MIT-green.svg?style=flat-square" alt="License">
  </p>
</div>

---

## 📖 Overview

**DBMS Mini Project (21CSC205P) – SRMIST**  
**Team**: Aayushmaan Chakraborty & Shashank Prasad  

This project implements a highly scalable **machine learning-based network intrusion detection system** using the renowned **NSL-KDD dataset** backed by a fully normalized **PostgreSQL** database. 

It is designed to classify network connections as either **`Normal`** or **`Intrusion`** with high precision, robust generalization, and prevent data leakage, making it an enterprise-grade prototype for real-world network security monitoring.

## 🚀 Key Features

* **Advanced Binary Classification:** Optimized Machine Learning pipeline to distinguish between legitimate traffic and malicious zero-day attack vectors.
* **Leakage Prevention:** Robust feature selection preventing artificial data leakage (e.g., elimination of `difficulty_level`), forcing the model to learn actual network behavioral patterns.
* **3NF Normalized RDBMS:** High-performance database schema enforcing strict 1NF/2NF/3NF constraints. Includes triggers for automatic intrusion audits and connection metrics.
* **REST API Backend:** A powerful Python backend utilizing **FastAPI** to serve real-time asynchronous ML predictions and data intelligence endpoints.
* **Synthetic Evaluation Suite:** Capable of passing rigorous synthetic evaluations (DoS, R2L, Probing) to ensure the agent doesn't overfit on static data.

---

## 🛠️ Technology Stack

| Domain | Technologies |
| :--- | :--- |
| **Backend Framework** | <img src="https://img.shields.io/badge/FastAPI-005571?style=flat-square&logo=fastapi" alt="FastAPI"> <img src="https://img.shields.io/badge/Uvicorn-499848?style=flat-square&logo=gunicorn" alt="Uvicorn"> |
| **Database ORM** | <img src="https://img.shields.io/badge/PostgreSQL-316192?style=flat-square&logo=postgresql" alt="PostgreSQL"> <img src="https://img.shields.io/badge/SQLAlchemy-D71F00?style=flat-square&logo=sqlite" alt="SQLAlchemy"> |
| **Machine Learning** | <img src="https://img.shields.io/badge/scikit--learn-F7931E?style=flat-square&logo=scikit-learn" alt="Scikit-Learn"> <img src="https://img.shields.io/badge/pandas-150458?style=flat-square&logo=pandas" alt="Pandas"> <img src="https://img.shields.io/badge/NumPy-013243?style=flat-square&logo=numpy" alt="NumPy"> |

---

## 📂 Repository Architecture

```text
IntrusionDetection/
├── ML-Based-Network-Intrusion-Detection-System/
│   ├── Intrusion_Detection.ipynb   # Main DB insertion & model training 
│   ├── intrusion_model.pkl         # Trained Random Forest joblib model
│   └── classification_report.txt   # Exported metrics from model runs
├── backend/                        # ⚡ FastAPI RESTful application
│   ├── routers/                    # Endpoint modules (predict, stats, connections)
│   ├── main.py                     # Uvicorn API entrypoint
│   ├── setup.sh & run.sh           # venv bootstrapping utilities
│   └── requirements.txt            # Backend-specific dependencies 
├── schema.sql                      # Current PostgreSQL dump (Tables, Views, Triggers)
├── populate_db.py                  # Script to ETL NSL-KDD into DB lookup tables
└── requirements.txt                # Core ML/Data analysis dependencies
```

---

## 🌐 FastAPI Backend

The project boasts a robust backend server exposing both ML capabilities and SQL aggregations for dashboard integration.

### Core Endpoints:
- `POST /predict`: Classify a network connection safely using the `.pkl` model (returns `Normal`/`Intrusion` probabilities).
- `GET /connections`: Paginated connection tables mapped deeply to PostgreSQL.
- `GET /dashboard`: Aggregated dashboard metrics (Attack distribution, volume stats).
- `GET /health`: Liveness probe for database and model connectivity.

### How to Run the Server
Simply execute our bash utility from the root folder to bootstrap the environment automatically:
```bash
# 1. Setup isolated environment
bash backend/setup.sh

# 2. Launch Uvicorn asynchronously
bash backend/run.sh
```
> [!TIP]
> Swagger UI documentation and testing environment will automatically spawn at [`http://localhost:8000/docs`](http://localhost:8000/docs).

---

## ⚙️ How to Reproduce the Environment

1. **Set up PostgreSQL Domain**
   - Create a local database named `intrusion_db`.
   - Restore the structural foundation: `psql intrusion_db < schema.sql`
   - Ensure your PostgreSQL server accepts standard connections or Unix sockets.

2. **Install Core ML Dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Populate Historical Datasets**
   - Place the [NSL-KDD dataset](https://www.unb.ca/cic/datasets/nsl.html) as `KDDTrain+.txt` inside the `ML-Based-Network-Intrusion-Detection-System/` directory.
   - Run `python populate_db.py` to ingest the baseline (~125k records).

4. **Retrain the Model (Optional)**
   - Open the primary notebook: `Intrusion_Detection.ipynb`
   - Run all cells to process, train the RandomForest classifier natively off of PostgreSQL data, and output local precision metrics.

---

## 📊 Results & Performance

* **Absolute Training Accuracy**: `~99.8%` on internal cross-validation splits.
* **Generalization**: The model successfully flags **80%+** of extreme synthetic attack permutations (mimicking active DoS and Probing mutations).
* **Primary Threat Vectors**: Feature importance calculations strongly flag `src_bytes`, `flag_id`, and `dst_host_srv_count` as the critical indicators over basic protocol variances.

---

## 🛡️ License & References
Distributed under the **MIT License**. Use for educational or developmental enterprise use cases safely.

* **NSL-KDD Authors**: [University of New Brunswick CIC](https://www.unb.ca/cic/datasets/nsl.html)
* **Kaggle Mirror**: [NSL-KDD Dataset](https://www.kaggle.com/datasets/hassan06/nslkdd)

