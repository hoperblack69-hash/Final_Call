import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import DataLoader
from sklearn.metrics import accuracy_score, classification_report
import pandas as pd
from tqdm import tqdm

from data.dataset import PhishingMultiModalDataset
from models.models import MultiChannelFusionNetwork

def train_model(model, train_loader, val_loader, num_epochs=5, learning_rate=1e-4, device='cuda'):
    model = model.to(device)
    criterion = nn.CrossEntropyLoss() # Multi-class classification (Benign, Phishing, Malware, etc.)
    optimizer = optim.Adam(model.parameters(), lr=learning_rate)
    
    print(f"Starting Training on {device}...")
    
    for epoch in range(num_epochs):
        model.train()
        train_loss = 0.0
        
        # Training Loop
        for batch in tqdm(train_loader, desc=f"Epoch {epoch+1}/{num_epochs}"):
            # Move to device
            llm_ids = batch['llm_input_ids'].to(device)
            llm_mask = batch['llm_attention_mask'].to(device)
            char_seq = batch['char_seq'].to(device)
            js_seq = batch['js_seq'].to(device)
            labels = batch['label'].to(device)
            
            optimizer.zero_grad()
            
            # Forward pass
            outputs = model(llm_ids, llm_mask, char_seq, js_seq)
            loss = criterion(outputs, labels)
            
            # Backward pass & optimize
            loss.backward()
            optimizer.step()
            
            train_loss += loss.item()
            
        avg_train_loss = train_loss / len(train_loader)
        
        # Validation Loop
        model.eval()
        val_loss = 0.0
        all_preds = []
        all_labels = []
        
        with torch.no_grad():
            for batch in val_loader:
                llm_ids = batch['llm_input_ids'].to(device)
                llm_mask = batch['llm_attention_mask'].to(device)
                char_seq = batch['char_seq'].to(device)
                js_seq = batch['js_seq'].to(device)
                labels = batch['label'].to(device)
                
                outputs = model(llm_ids, llm_mask, char_seq, js_seq)
                loss = criterion(outputs, labels)
                val_loss += loss.item()
                
                _, preds = torch.max(outputs, 1)
                all_preds.extend(preds.cpu().numpy())
                all_labels.extend(labels.cpu().numpy())
                
        avg_val_loss = val_loss / len(val_loader)
        val_acc = accuracy_score(all_labels, all_preds)
        
        print(f"Epoch {epoch+1} - Train Loss: {avg_train_loss:.4f} | Val Loss: {avg_val_loss:.4f} | Val Acc: {val_acc:.4f}")
        
    print("\nTraining Complete.")
    print("Final Classification Report:")
    print(classification_report(all_labels, all_preds, target_names=["Benign", "Phishing", "Malware"]))
    
    # Save Model Weights
    torch.save(model.state_dict(), 'models/multi_channel_phishing.pth')
    print("Model saved to models/multi_channel_phishing.pth")


if __name__ == "__main__":
    # --- Integration Test / Dry Run Setup ---
    print("Running integration sanity check on training loops...")
    
    # 1. Create a tiny dummy dataset
    dummy_data = pd.DataFrame({
        'url': [
            'http://example.com/login', 
            'http://phishing-site.xyz/update', 
            'http://malware-drop.ru/payload.exe',
            'http://google.com'
        ] * 4, # 16 examples
        'js_trace': [
            'var a=1;', 
            'document.getElementById("pass").value="hacked";',
            'eval(atob(""));',
            'console.log("hello");'
        ] * 4,
        'label': [0, 1, 2, 0] * 4
    })
    
    dataset = PhishingMultiModalDataset(dummy_data)
    
    # Minimal batch size & workers for quick test
    train_loader = DataLoader(dataset, batch_size=4, shuffle=True)
    val_loader = DataLoader(dataset, batch_size=4, shuffle=False)
    
    # 2. Init Model
    model = MultiChannelFusionNetwork(num_classes=3)
    
    # Use CPU for rapid testing if no GPU is available or to bypass memory limits
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    
    # 3. Quick Run (1 epoch)
    train_model(model, train_loader, val_loader, num_epochs=1, device=device)
