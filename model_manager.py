import joblib
from sklearn.ensemble import RandomForestClassifier, VotingClassifier
from xgboost import XGBClassifier

class IDSModelManager:
    def __init__(self):
        self.rf = RandomForestClassifier(n_estimators=100, random_state=42)
        self.xgb = XGBClassifier(use_label_encoder=False, eval_metric='mlogloss', random_state=42)
        self.ensemble = VotingClassifier(
            estimators=[('rf', self.rf), ('xgb', self.xgb)],
            voting='soft'
        )

    def save_model(self, path='trained_ids_model.pkl'):
        joblib.dump(self.ensemble, path)