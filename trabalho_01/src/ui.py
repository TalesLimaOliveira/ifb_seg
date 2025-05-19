# Contents of the file: /ifb_seg/ifb_seg/src/ui.py

import streamlit as st

def display_title():
    """Display the title of the application."""
    st.title("Criptografia")

def select_encryption_algorithm():
    """Create a dropdown for selecting the encryption algorithm."""
    return st.selectbox("Escolha o algoritmo de criptografia", ["DES", "AES", "RSA"])

def select_mode():
    """Create radio buttons for selecting the mode of operation."""
    return st.radio("Modo de operação", ["Criptografar", "Descriptografar"])

def input_key(max_chars=32):
    """Create an input field for the encryption key."""
    return st.text_input("Chave (hexadecimal)", max_chars=max_chars)

def input_text_area(label, height=150):
    """Create a text area for user input."""
    return st.text_area(label, height=height)

def display_result(result, label):
    """Display the result of encryption or decryption."""
    st.success(label + ":")
    st.code(result)

def display_error(message):
    """Display an error message."""
    st.error(message)