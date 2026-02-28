# ML-Based Network Intrusion Detection System

**DBMS Mini Project (21CSC205P) – SRMIST**

**Team**: Aayushmaan Chakraborty & Shashank Prasad

This project implements a **machine learning-based network intrusion detection system** using the **NSL-KDD dataset** and **PostgreSQL** database. The system is designed to classify network connections as either **Normal** or **Intrusion** with high precision and robust generalization.

## 🚀 Key Features

- **Binary Classification**: Optimized to distinguish between legitimate traffic and diverse attack vectors.
- **Leakage Prevention**: Robust feature selection that eliminates data leakage (e.g., removing `difficulty_level`), ensuring the model learns actual network patterns.
- **Normalized DBMS**: Stores data in a PostgreSQL database with lookup tables for protocols, services, flags, and attacks.
- **Synthetic Evaluation Suite**: Includes a set of 10 diverse synthetic test cases (DoS, R2L, Probing, etc.) using class-specific baselines to verify model generalization.
- **Unix Domain Socket Support**: Seamless database integration using local OS-level authentication.

## 📁 Repository Contents

| File | Description |
| :--- | :--- |
| `ML-Based-Network-Intrusion-Detection-System-/Intrusion_Detection.ipynb` | Main Jupyter notebook: data processing, DB insertion, model training & refined evaluation. |
| `schema.sql` | PostgreSQL schema (lookup tables + normalized `connections` table). |
| `populate_db.py` | Python script to populate the PostgreSQL database from raw NSL-KDD data. |
| `ML-Based-Network-Intrusion-Detection-System-/intrusion_model.pkl` | Trained Random Forest model (saved with joblib). |
| `ML-Based-Network-Intrusion-Detection-System-/classification_report.txt` | Detailed metrics from the latest model run. |
| `requirements.txt` | Project dependencies. |

## 🛠 Tech Stack

- **Database**: PostgreSQL (via SQLAlchemy)
- **Language**: Python 3.11+
- **Machine Learning**: Scikit-learn (RandomForestClassifier)
- **Data Analysis**: Pandas, NumPy
- **Visualization**: Matplotlib, Seaborn

## ⚙️ How to Reproduce

1. **Set up PostgreSQL**
   - Create a local database named `intrusion_db`.
   - Ensure your PostgreSQL server is running and accessible via Unix domain sockets.

2. **Install Dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Populate Database**
   - Ensure `KDDTrain+.txt` is in the `ML-Based-Network-Intrusion-Detection-System-/` directory.
   - Run the population logic in the notebook or via a standalone script to load the ~125k records into PostgreSQL.

4. **Run the Model**
   - Open `ML-Based-Network-Intrusion-Detection-System-/Intrusion_Detection.ipynb`.
   - The notebook connects automatically to `intrusion_db` via the current OS user.
   - Run all cells to train the model and see the **Section 9: Synthetic Data Evaluation** results.

## 📊 Results Overview

- **Training Accuracy**: ~99.8% on the NSL-KDD test split.
- **Generalization**: The model successfully identifies **80%** of synthetic attack scenarios (unseen patterns) correctly, showing high reliability across DoS and Probing attacks.
- **Primary Indicators**: Feature importance analysis shows `src_bytes`, `flag_id`, and `dst_host_srv_count` as the most critical features for detection.

## 🛡 License

MIT License – Feel free to use for educational purposes.

## 🔗 References

- **NSL-KDD Dataset**: [University of New Brunswick CIC](https://www.unb.ca/cic/datasets/nsl.html)
- **Kaggle Link**: [NSL-KDD Dataset](https://www.kaggle.com/datasets/hassan06/nslkdd)
