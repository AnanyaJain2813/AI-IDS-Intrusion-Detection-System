"""
GRU Autoencoder for sequence-based anomaly detection.

Architecture:
    Encoder: GRU that reads the (N, input_dim) sequence and compresses it
             into a fixed-size hidden state (the bottleneck).
    Decoder: GRU that receives the bottleneck replicated N times and
             reconstructs the original sequence.
    Output:  Linear layer mapping hidden_dim -> input_dim per timestep.

Anomaly scoring:
    reconstruction_error() returns the mean-squared error between the input
    window and the reconstructed output.  Higher error = more anomalous.
"""
import torch
import torch.nn as nn


class GRUAutoencoder(nn.Module):
    def __init__(self, input_dim=6, hidden_dim=32):
        super().__init__()
        self.input_dim = input_dim
        self.hidden_dim = hidden_dim

        self.encoder = nn.GRU(input_dim, hidden_dim, batch_first=True)
        self.decoder = nn.GRU(hidden_dim, hidden_dim, batch_first=True)
        self.output_layer = nn.Linear(hidden_dim, input_dim)

    def forward(self, x):
        """
        x: (batch, seq_len, input_dim)
        returns: (batch, seq_len, input_dim) — the reconstruction
        """
        batch_size, seq_len, _ = x.size()

        # Encode: read full sequence, keep only final hidden state
        _, hidden = self.encoder(x)  # hidden: (1, batch, hidden_dim)

        # Decode: replicate the bottleneck across all timesteps
        decoder_input = hidden.permute(1, 0, 2).repeat(1, seq_len, 1)  # (batch, seq_len, hidden_dim)
        decoder_output, _ = self.decoder(decoder_input, hidden)  # (batch, seq_len, hidden_dim)

        # Project back to input space
        reconstructed = self.output_layer(decoder_output)  # (batch, seq_len, input_dim)
        return reconstructed


def reconstruction_error(model, window_tensor):
    """
    Compute mean-squared reconstruction error for a single window.

    window_tensor: (seq_len, input_dim) or (1, seq_len, input_dim)
    returns: float — the MSE
    """
    model.eval()
    with torch.no_grad():
        if window_tensor.dim() == 2:
            window_tensor = window_tensor.unsqueeze(0)  # add batch dim
        reconstructed = model(window_tensor)
        mse = nn.functional.mse_loss(reconstructed, window_tensor).item()
    return mse
