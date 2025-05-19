# File: /ifb_seg/ifb_seg/src/app.py

import streamlit as st
import os
import binascii
import crypto_utils  # Importa funções de criptografia do módulo crypto_utils.py
import ui  # Importa funções de interface do módulo ui.py

# Exibe o título da aplicação
ui.display_title()

# Seleção do algoritmo de criptografia
option = ui.select_encryption_algorithm()

# Seleção do modo de operação (Criptografar/Descriptografar)
mode = ui.select_mode()

def get_key_length_bytes(algorithm):
    if algorithm == "DES":
        return 8
    elif algorithm == "AES":
        return 16  # Default for AES-128
    return None

def get_key_length_hex(algorithm):
    if algorithm == "DES":
        return 16  # 8 bytes = 16 hex chars
    elif algorithm == "AES":
        return 32  # 16 bytes = 32 hex chars (default)
    return None

# Lógica para algoritmos simétricos (DES, AES)
if option in ["DES", "AES"]:
    key_bytes = None
    key_length_bytes = get_key_length_bytes(option)
    key_length_hex = get_key_length_hex(option)

    # Para AES, permitir escolha do tamanho da chave
    if option == "AES":
        aes_size = st.selectbox("Tamanho da chave AES (bits)", [128, 192, 256], index=0)
        key_length_bytes = aes_size // 8
        key_length_hex = key_length_bytes * 2

    # Só permite gerar automaticamente se for para criptografar
    if mode == "Criptografar":
        key_mode = st.radio("Modo da chave", ["Informar chave", "Gerar automaticamente"])
    else:
        key_mode = "Informar chave"
        st.info("Para descriptografar, informe a chave utilizada na criptografia.")

    if key_mode == "Informar chave":
        key_input = ui.input_key(max_chars=key_length_hex)
        if key_input:
            try:
                key_bytes = bytes.fromhex(key_input)
                if len(key_bytes) != key_length_bytes:
                    ui.display_error(f"A chave deve ter exatamente {key_length_bytes} bytes ({key_length_hex} caracteres hexadecimais).")
                    key_bytes = None
            except binascii.Error:
                ui.display_error("A chave precisa estar em hexadecimal válido.")
                key_bytes = None
    elif key_mode == "Gerar automaticamente":
        # Usa session_state para manter a chave até o usuário pedir para atualizar
        key_session_name = f"auto_key_{option}_{key_length_bytes}"
        if key_session_name not in st.session_state:
            st.session_state[key_session_name] = os.urandom(key_length_bytes)
        if st.button("Atualizar chave"):
            st.session_state[key_session_name] = os.urandom(key_length_bytes)
        key_bytes = st.session_state[key_session_name]
        st.info(f"Chave gerada automaticamente (hex): {key_bytes.hex()}")

    text = st.text_area("Texto", height=68)
    if st.button("CONFIRMAR"):
        if key_bytes and text:
            if mode == "Criptografar":
                if option == "DES":
                    result = crypto_utils.encrypt_des(text, key_bytes)
                else:
                    result = crypto_utils.encrypt_aes(text, key_bytes)
                ui.display_result(result, "Texto criptografado")
                st.success(f"Chave utilizada (hex): {key_bytes.hex()}")
            else:
                try:
                    if option == "DES":
                        result = crypto_utils.decrypt_des(text, key_bytes)
                    else:
                        result = crypto_utils.decrypt_aes(text, key_bytes)
                    ui.display_result(result, "Texto original")
                except Exception as e:
                    ui.display_error("Erro na descriptografia: " + str(e))

# Lógica para algoritmo assimétrico (RSA)
elif option == "RSA":
    st.subheader("Gerar ou colar chaves RSA")
    key_mode = st.radio("Modo da chave RSA", ["Informar chave", "Gerar automaticamente"])
    if key_mode == "Gerar automaticamente":
        if "rsa_private" not in st.session_state:
            private_key, public_key = crypto_utils.generate_rsa_keys()
            st.session_state.rsa_private = private_key.decode()
            st.session_state.rsa_public = public_key.decode()
        st.text_area("Chave Pública Gerada", st.session_state.rsa_public, height=100)
        st.text_area("Chave Privada Gerada", st.session_state.rsa_private, height=100)
        public_key = st.session_state.rsa_public
        private_key = st.session_state.rsa_private
    else:
        public_key = ui.input_text_area("Chave Pública", height=100)
        private_key = ui.input_text_area("Chave Privada", height=100)

    text = ui.input_text_area("Texto")
    if st.button("CONFIRMAR"):
        if text:
            if mode == "Criptografar":
                try:
                    result = crypto_utils.encrypt_rsa(text, public_key.encode())
                    ui.display_result(result, "Texto criptografado")
                except Exception as e:
                    ui.display_error("Erro na criptografia: " + str(e))
            else:
                try:
                    result = crypto_utils.decrypt_rsa(text, private_key.encode())
                    ui.display_result(result, "Texto original")
                except Exception as e:
                    ui.display_error("Erro na descriptografia: " + str(e))