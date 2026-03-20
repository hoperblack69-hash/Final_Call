import torch
import numpy as np
from transformers import AutoTokenizer

from models.models import MultiChannelFusionNetwork

class PhishingDetector:
    def __init__(self, model_path, llm_model_name="distilbert-base-uncased", device='cpu'):
        self.device = torch.device(device)
        self.tokenizer = AutoTokenizer.from_pretrained(llm_model_name)
        
        self.max_url_len = 200
        self.max_js_len = 500
        self.char_vocab_size = 128
        
        self.model = MultiChannelFusionNetwork(num_classes=3)
        # Load weights (assuming trained model is saved)
        try:
            self.model.load_state_dict(torch.load(model_path, map_location=self.device))
            print(f"Loaded weights from {model_path}")
        except FileNotFoundError:
            print("Warning: Model weights not found. Using untrained initialization for inference test.")
            
        self.model.to(self.device)
        self.model.eval()
        
        # Label mapping
        self.classes = {0: "Benign", 1: "Phishing", 2: "Malware"}
        
    def _get_char_encoding(self, text, max_len):
        encoded = np.zeros(max_len, dtype=np.int64)
        for i, char in enumerate(text[:max_len]):
            val = ord(char)
            encoded[i] = val if val < self.char_vocab_size else 0
        return torch.tensor(encoded, dtype=torch.long)

    @torch.no_grad()
    def predict(self, url: str, js_trace: str = ""):
        # LLM channel
        encoded_url_llm = self.tokenizer(
            url,
            padding="max_length",
            truncation=True,
            max_length=self.max_url_len,
            return_tensors="pt"
        )
        
        # CNN channel
        encoded_url_char = self._get_char_encoding(url, self.max_url_len).unsqueeze(0)
        
        # LSTM channel
        encoded_js = self._get_char_encoding(js_trace, self.max_js_len).unsqueeze(0)
        
        # To device
        llm_ids = encoded_url_llm['input_ids'].to(self.device)
        llm_mask = encoded_url_llm['attention_mask'].to(self.device)
        char_seq = encoded_url_char.to(self.device)
        js_seq = encoded_js.to(self.device)
        
        # Inference
        outputs, _ = self.model(llm_ids, llm_mask, char_seq, js_seq)
        
        # Softmax probabilities
        probs = torch.nn.functional.softmax(outputs, dim=1).squeeze(0).cpu().numpy()
        
        pred_idx = np.argmax(probs)
        prediction = self.classes[pred_idx]
        
        return {
            "url": url,
            "prediction": prediction,
            "probabilities": {self.classes[i]: float(probs[i]) for i in range(3)}
        }

if __name__ == "__main__":
    detector = PhishingDetector(model_path="models/multi_channel_phishing.pth")
    
    test_urls = [
        ("http://secure-login.apple-verification.xyz/auth", "var user = document.forms[0].username.value; send_to_attacker(user);"),
        ("https://github.com/pytorch/pytorch", "console.log('loaded');")
    ]
    
    print("\n--- Running Inference Tests ---")
    for url, js in test_urls:
        result = detector.predict(url, js_trace=js)
        print(f"\nURL: {result['url']}")
        print(f"Prediction: {result['prediction']}")
        print(f"Probabilities: {result['probabilities']}")
