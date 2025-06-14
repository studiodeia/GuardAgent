# GuardAgent ML Models - Implementação Própria

## 🎯 Estratégia de ML para LLM Security

### Modelos Necessários
```yaml
ml_models:
  pii_detection:
    base_model: "neuralmind/bert-base-portuguese-cased"
    task: "named_entity_recognition"
    entities: ["CPF", "CNPJ", "EMAIL", "PHONE", "ADDRESS", "CREDIT_CARD"]
    
  prompt_injection:
    base_model: "microsoft/DialoGPT-medium"
    task: "binary_classification"
    classes: ["safe", "injection"]
    
  anomaly_detection:
    algorithm: "isolation_forest"
    features: ["text_length", "entropy", "special_chars", "patterns"]
    
  content_classification:
    base_model: "sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2"
    task: "multi_label_classification"
    labels: ["sensitive", "business", "personal", "technical"]
```

## 🏗️ Implementação dos Modelos

### 1. PII Detection Model

```python
# ml/models/pii_detector.py
import torch
from transformers import AutoTokenizer, AutoModelForTokenClassification
from transformers import pipeline
import re
import spacy
from typing import List, Dict, Tuple

class PIIDetector:
    def __init__(self, model_path: str = "neuralmind/bert-base-portuguese-cased"):
        self.tokenizer = AutoTokenizer.from_pretrained(model_path)
        self.model = AutoModelForTokenClassification.from_pretrained(model_path)
        self.nlp = spacy.load("pt_core_news_sm")
        
        # Regex patterns for Brazilian PII
        self.regex_patterns = {
            'cpf': re.compile(r'\b\d{3}\.?\d{3}\.?\d{3}-?\d{2}\b'),
            'cnpj': re.compile(r'\b\d{2}\.?\d{3}\.?\d{3}/?\d{4}-?\d{2}\b'),
            'phone': re.compile(r'\(?(\d{2})\)?\s?9?\d{4}-?\d{4}'),
            'email': re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),
            'credit_card': re.compile(r'\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b'),
            'cep': re.compile(r'\b\d{5}-?\d{3}\b'),
        }
        
        # Initialize NER pipeline
        self.ner_pipeline = pipeline(
            "ner",
            model=self.model,
            tokenizer=self.tokenizer,
            aggregation_strategy="simple"
        )
    
    def detect_pii(self, text: str) -> Dict[str, List[Dict]]:
        """
        Detect PII using both regex and ML models
        """
        results = {
            'regex_matches': self._detect_with_regex(text),
            'ml_matches': self._detect_with_ml(text),
            'spacy_matches': self._detect_with_spacy(text)
        }
        
        # Combine and deduplicate results
        combined = self._combine_results(results)
        
        return {
            'pii_found': len(combined) > 0,
            'confidence': self._calculate_confidence(combined),
            'entities': combined,
            'masked_text': self._mask_pii(text, combined)
        }
    
    def _detect_with_regex(self, text: str) -> List[Dict]:
        """Fast regex-based detection"""
        matches = []
        
        for pii_type, pattern in self.regex_patterns.items():
            for match in pattern.finditer(text):
                matches.append({
                    'type': pii_type,
                    'text': match.group(),
                    'start': match.start(),
                    'end': match.end(),
                    'confidence': 0.95,
                    'method': 'regex'
                })
        
        return matches
    
    def _detect_with_ml(self, text: str) -> List[Dict]:
        """ML-based NER detection"""
        try:
            entities = self.ner_pipeline(text)
            matches = []
            
            for entity in entities:
                # Map model labels to our PII types
                pii_type = self._map_entity_label(entity['entity_group'])
                if pii_type:
                    matches.append({
                        'type': pii_type,
                        'text': entity['word'],
                        'start': entity['start'],
                        'end': entity['end'],
                        'confidence': entity['score'],
                        'method': 'ml'
                    })
            
            return matches
        except Exception as e:
            print(f"ML detection error: {e}")
            return []
    
    def _detect_with_spacy(self, text: str) -> List[Dict]:
        """SpaCy NER detection"""
        doc = self.nlp(text)
        matches = []
        
        for ent in doc.ents:
            pii_type = self._map_spacy_label(ent.label_)
            if pii_type:
                matches.append({
                    'type': pii_type,
                    'text': ent.text,
                    'start': ent.start_char,
                    'end': ent.end_char,
                    'confidence': 0.8,
                    'method': 'spacy'
                })
        
        return matches
    
    def _map_entity_label(self, label: str) -> str:
        """Map model entity labels to PII types"""
        mapping = {
            'PER': 'person_name',
            'ORG': 'organization',
            'LOC': 'location',
            'MISC': 'miscellaneous'
        }
        return mapping.get(label)
    
    def _map_spacy_label(self, label: str) -> str:
        """Map SpaCy labels to PII types"""
        mapping = {
            'PERSON': 'person_name',
            'ORG': 'organization',
            'GPE': 'location',
            'LOC': 'location'
        }
        return mapping.get(label)
    
    def _combine_results(self, results: Dict) -> List[Dict]:
        """Combine and deduplicate results from different methods"""
        all_matches = []
        
        for method, matches in results.items():
            all_matches.extend(matches)
        
        # Sort by position
        all_matches.sort(key=lambda x: x['start'])
        
        # Remove overlapping matches (keep highest confidence)
        deduplicated = []
        for match in all_matches:
            overlapping = False
            for existing in deduplicated:
                if self._is_overlapping(match, existing):
                    if match['confidence'] > existing['confidence']:
                        deduplicated.remove(existing)
                        deduplicated.append(match)
                    overlapping = True
                    break
            
            if not overlapping:
                deduplicated.append(match)
        
        return deduplicated
    
    def _is_overlapping(self, match1: Dict, match2: Dict) -> bool:
        """Check if two matches overlap"""
        return not (match1['end'] <= match2['start'] or match2['end'] <= match1['start'])
    
    def _calculate_confidence(self, matches: List[Dict]) -> float:
        """Calculate overall confidence score"""
        if not matches:
            return 0.0
        
        total_confidence = sum(match['confidence'] for match in matches)
        return min(total_confidence / len(matches), 1.0)
    
    def _mask_pii(self, text: str, matches: List[Dict]) -> str:
        """Mask detected PII in text"""
        masked_text = text
        
        # Sort matches by position (reverse order to maintain indices)
        matches.sort(key=lambda x: x['start'], reverse=True)
        
        for match in matches:
            mask = f"[{match['type'].upper()}]"
            masked_text = (
                masked_text[:match['start']] + 
                mask + 
                masked_text[match['end']:]
            )
        
        return masked_text

# Training script for custom PII model
class PIIModelTrainer:
    def __init__(self, base_model: str = "neuralmind/bert-base-portuguese-cased"):
        self.base_model = base_model
        self.tokenizer = AutoTokenizer.from_pretrained(base_model)
        
    def prepare_training_data(self, texts: List[str], labels: List[List[str]]):
        """Prepare data for NER training"""
        # Convert to IOB format
        tokenized_inputs = []
        tokenized_labels = []
        
        for text, label_list in zip(texts, labels):
            tokens = self.tokenizer.tokenize(text)
            # Convert labels to IOB format
            iob_labels = self._convert_to_iob(tokens, label_list)
            
            tokenized_inputs.append(tokens)
            tokenized_labels.append(iob_labels)
        
        return tokenized_inputs, tokenized_labels
    
    def train_model(self, train_data, val_data, output_dir: str):
        """Train custom PII detection model"""
        from transformers import TrainingArguments, Trainer
        
        training_args = TrainingArguments(
            output_dir=output_dir,
            num_train_epochs=3,
            per_device_train_batch_size=16,
            per_device_eval_batch_size=16,
            warmup_steps=500,
            weight_decay=0.01,
            logging_dir=f"{output_dir}/logs",
            evaluation_strategy="epoch",
            save_strategy="epoch",
            load_best_model_at_end=True,
        )
        
        model = AutoModelForTokenClassification.from_pretrained(
            self.base_model,
            num_labels=len(self._get_label_list())
        )
        
        trainer = Trainer(
            model=model,
            args=training_args,
            train_dataset=train_data,
            eval_dataset=val_data,
            tokenizer=self.tokenizer,
        )
        
        trainer.train()
        trainer.save_model()
        
        return model
```

### 2. Prompt Injection Detection Model

```python
# ml/models/injection_detector.py
import torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification
from transformers import pipeline
import numpy as np
from typing import Dict, List
import re

class PromptInjectionDetector:
    def __init__(self, model_path: str = "microsoft/DialoGPT-medium"):
        self.tokenizer = AutoTokenizer.from_pretrained(model_path)
        self.model = AutoModelForSequenceClassification.from_pretrained(model_path)
        
        # Pattern-based detection rules
        self.injection_patterns = [
            {
                'name': 'ignore_instructions',
                'pattern': re.compile(r'(?i)(ignore|forget|disregard).*(previous|above|instruction|rule|prompt)'),
                'severity': 'high',
                'confidence': 0.9
            },
            {
                'name': 'role_manipulation',
                'pattern': re.compile(r'(?i)(you are now|act as|pretend to be|roleplay as|assume the role)'),
                'severity': 'medium',
                'confidence': 0.85
            },
            {
                'name': 'jailbreak_dan',
                'pattern': re.compile(r'(?i)(DAN|do anything now|developer mode|unrestricted|no limitations)'),
                'severity': 'critical',
                'confidence': 0.95
            },
            {
                'name': 'system_prompt_leak',
                'pattern': re.compile(r'(?i)(show|reveal|tell me).*(system prompt|instructions|rules)'),
                'severity': 'high',
                'confidence': 0.9
            },
            {
                'name': 'code_injection',
                'pattern': re.compile(r'(?i)(execute|run|eval).*(code|script|command)'),
                'severity': 'critical',
                'confidence': 0.85
            }
        ]
        
        # Initialize classification pipeline
        self.classifier = pipeline(
            "text-classification",
            model=self.model,
            tokenizer=self.tokenizer,
            return_all_scores=True
        )
    
    def detect_injection(self, text: str) -> Dict:
        """
        Detect prompt injection using pattern matching and ML
        """
        # Pattern-based detection
        pattern_results = self._detect_with_patterns(text)
        
        # ML-based detection
        ml_results = self._detect_with_ml(text)
        
        # Combine results
        combined_confidence = max(
            pattern_results['confidence'],
            ml_results['confidence']
        )
        
        is_injection = combined_confidence > 0.7
        
        return {
            'is_injection': is_injection,
            'confidence': combined_confidence,
            'risk_level': self._calculate_risk_level(combined_confidence),
            'pattern_matches': pattern_results['matches'],
            'ml_prediction': ml_results,
            'explanation': self._generate_explanation(pattern_results, ml_results)
        }
    
    def _detect_with_patterns(self, text: str) -> Dict:
        """Pattern-based injection detection"""
        matches = []
        max_confidence = 0.0
        
        for pattern_info in self.injection_patterns:
            if pattern_info['pattern'].search(text):
                matches.append({
                    'name': pattern_info['name'],
                    'severity': pattern_info['severity'],
                    'confidence': pattern_info['confidence']
                })
                max_confidence = max(max_confidence, pattern_info['confidence'])
        
        return {
            'matches': matches,
            'confidence': max_confidence
        }
    
    def _detect_with_ml(self, text: str) -> Dict:
        """ML-based injection detection"""
        try:
            # Truncate text if too long
            max_length = 512
            if len(text) > max_length:
                text = text[:max_length]
            
            results = self.classifier(text)
            
            # Assuming binary classification: safe (0) vs injection (1)
            injection_score = 0.0
            for result in results[0]:
                if result['label'] == 'LABEL_1':  # Injection class
                    injection_score = result['score']
                    break
            
            return {
                'confidence': injection_score,
                'raw_scores': results[0]
            }
        except Exception as e:
            print(f"ML detection error: {e}")
            return {'confidence': 0.0, 'raw_scores': []}
    
    def _calculate_risk_level(self, confidence: float) -> str:
        """Calculate risk level based on confidence"""
        if confidence >= 0.9:
            return 'critical'
        elif confidence >= 0.7:
            return 'high'
        elif confidence >= 0.5:
            return 'medium'
        elif confidence >= 0.3:
            return 'low'
        else:
            return 'none'
    
    def _generate_explanation(self, pattern_results: Dict, ml_results: Dict) -> str:
        """Generate human-readable explanation"""
        explanations = []
        
        if pattern_results['matches']:
            pattern_names = [match['name'] for match in pattern_results['matches']]
            explanations.append(f"Pattern matches: {', '.join(pattern_names)}")
        
        if ml_results['confidence'] > 0.5:
            explanations.append(f"ML model confidence: {ml_results['confidence']:.2f}")
        
        if not explanations:
            return "No injection patterns detected"
        
        return "; ".join(explanations)

# Training script for custom injection model
class InjectionModelTrainer:
    def __init__(self, base_model: str = "microsoft/DialoGPT-medium"):
        self.base_model = base_model
        self.tokenizer = AutoTokenizer.from_pretrained(base_model)
        
    def prepare_training_data(self, texts: List[str], labels: List[int]):
        """Prepare data for binary classification training"""
        encodings = self.tokenizer(
            texts,
            truncation=True,
            padding=True,
            max_length=512,
            return_tensors='pt'
        )
        
        return {
            'input_ids': encodings['input_ids'],
            'attention_mask': encodings['attention_mask'],
            'labels': torch.tensor(labels)
        }
    
    def train_model(self, train_data, val_data, output_dir: str):
        """Train custom injection detection model"""
        from transformers import TrainingArguments, Trainer
        
        training_args = TrainingArguments(
            output_dir=output_dir,
            num_train_epochs=3,
            per_device_train_batch_size=8,
            per_device_eval_batch_size=8,
            warmup_steps=500,
            weight_decay=0.01,
            logging_dir=f"{output_dir}/logs",
            evaluation_strategy="epoch",
            save_strategy="epoch",
            load_best_model_at_end=True,
            metric_for_best_model="eval_accuracy",
        )
        
        model = AutoModelForSequenceClassification.from_pretrained(
            self.base_model,
            num_labels=2  # Binary classification
        )
        
        trainer = Trainer(
            model=model,
            args=training_args,
            train_dataset=train_data,
            eval_dataset=val_data,
            tokenizer=self.tokenizer,
            compute_metrics=self._compute_metrics,
        )
        
        trainer.train()
        trainer.save_model()
        
        return model
    
    def _compute_metrics(self, eval_pred):
        """Compute metrics for evaluation"""
        from sklearn.metrics import accuracy_score, precision_recall_fscore_support
        
        predictions, labels = eval_pred
        predictions = np.argmax(predictions, axis=1)
        
        accuracy = accuracy_score(labels, predictions)
        precision, recall, f1, _ = precision_recall_fscore_support(labels, predictions, average='weighted')
        
        return {
            'accuracy': accuracy,
            'f1': f1,
            'precision': precision,
            'recall': recall
        }
```

### 3. Model Serving Infrastructure

```python
# ml/serving/model_server.py
import torch
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import uvicorn
import asyncio
from typing import Dict, List
import logging

app = FastAPI(title="GuardAgent ML Models API")

class PIIRequest(BaseModel):
    text: str
    mask_pii: bool = True

class InjectionRequest(BaseModel):
    text: str

class PIIResponse(BaseModel):
    pii_found: bool
    confidence: float
    entities: List[Dict]
    masked_text: str

class InjectionResponse(BaseModel):
    is_injection: bool
    confidence: float
    risk_level: str
    explanation: str

class ModelServer:
    def __init__(self):
        self.pii_detector = None
        self.injection_detector = None
        self.models_loaded = False
    
    async def load_models(self):
        """Load ML models asynchronously"""
        try:
            self.pii_detector = PIIDetector()
            self.injection_detector = PromptInjectionDetector()
            self.models_loaded = True
            logging.info("Models loaded successfully")
        except Exception as e:
            logging.error(f"Failed to load models: {e}")
            raise
    
    async def detect_pii(self, text: str, mask_pii: bool = True) -> Dict:
        """Detect PII in text"""
        if not self.models_loaded:
            raise HTTPException(status_code=503, detail="Models not loaded")
        
        try:
            result = self.pii_detector.detect_pii(text)
            if not mask_pii:
                result.pop('masked_text', None)
            return result
        except Exception as e:
            logging.error(f"PII detection error: {e}")
            raise HTTPException(status_code=500, detail="PII detection failed")
    
    async def detect_injection(self, text: str) -> Dict:
        """Detect prompt injection in text"""
        if not self.models_loaded:
            raise HTTPException(status_code=503, detail="Models not loaded")
        
        try:
            result = self.injection_detector.detect_injection(text)
            return result
        except Exception as e:
            logging.error(f"Injection detection error: {e}")
            raise HTTPException(status_code=500, detail="Injection detection failed")

# Global model server instance
model_server = ModelServer()

@app.on_event("startup")
async def startup_event():
    await model_server.load_models()

@app.post("/detect/pii", response_model=PIIResponse)
async def detect_pii(request: PIIRequest):
    result = await model_server.detect_pii(request.text, request.mask_pii)
    return PIIResponse(**result)

@app.post("/detect/injection", response_model=InjectionResponse)
async def detect_injection(request: InjectionRequest):
    result = await model_server.detect_injection(request.text)
    return InjectionResponse(**result)

@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "models_loaded": model_server.models_loaded
    }

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
```

Esta implementação fornece modelos ML próprios para PII detection e prompt injection, com APIs para serving. Quer que eu continue com a implementação do storage e cache para os modelos?
