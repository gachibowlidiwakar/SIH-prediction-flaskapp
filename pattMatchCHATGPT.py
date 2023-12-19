import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from keras.models import Sequential
from keras.layers import Conv1D, MaxPooling1D, Flatten, Dense, Embedding
from keras.preprocessing.text import Tokenizer
from keras.utils import pad_sequences

# Load the whitelist CSV file
whitelist = pd.read_csv("whitelist.csv")
whitelist["domain"] = whitelist["domain"].str.strip()

# Generate phishing data for demonstration
phishing_data = pd.DataFrame({
    'domain': ['phish1.com', 'phish2.com', 'phish3.com'],
    'label': [1, 1, 1]  # 1 for phishing
})

# Combine whitelist and phishing data
combined_data = pd.concat([whitelist, phishing_data], ignore_index=True)

# Shuffle the data
combined_data = combined_data.sample(frac=1).reset_index(drop=True)

# Tokenize and pad the domain names
tokenizer = Tokenizer()
tokenizer.fit_on_texts(combined_data['domain'])
sequences = tokenizer.texts_to_sequences(combined_data['domain'])
padded_sequences = pad_sequences(sequences)

# Encode labels
label_encoder = LabelEncoder()
labels = label_encoder.fit_transform(combined_data['label'])

# Split the data into training and testing sets
X_train, X_test, y_train, y_test = train_test_split(
    padded_sequences, labels, test_size=0.2, random_state=42
)

# Build the CNN model
embedding_dim = 50
vocab_size = len(tokenizer.word_index) + 1

model = Sequential()
model.add(Embedding(input_dim=vocab_size, output_dim=embedding_dim, input_length=padded_sequences.shape[1]))
model.add(Conv1D(filters=32, kernel_size=3, activation='relu'))
model.add(MaxPooling1D(pool_size=2))
model.add(Flatten())
model.add(Dense(units=64, activation='relu'))
model.add(Dense(units=1, activation='sigmoid'))

model.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])

# Train the model
model.fit(X_train, y_train, epochs=5, batch_size=32, validation_data=(X_test, y_test))

# Evaluate the model
loss, accuracy = model.evaluate(X_test, y_test)
print(f"Test Loss: {loss:.4f}")
print(f"Test Accuracy: {accuracy * 100:.2f}%")
