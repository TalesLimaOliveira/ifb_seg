# File: /ifb_seg/ifb_seg/src/app.py

import streamlit as st
import crypto_utils  # Importa funções de criptografia do módulo crypto_utils.py
import ui  # Importa funções de interface do módulo ui.py

# Exibe o título da aplicação
ui.display_title()

# Seleção do algoritmo de criptografia
option = ui.select_encryption_algorithm()

# Seleção do modo de operação (Criptografar/Descriptografar)
mode = ui.select_mode()

# Lógica para algoritmos simétricos (DES, AES)
if option in ["DES", "AES"]:
    key_input = ui.input_key(max_chars=32)  # Entrada da chave em hexadecimal

    if key_input:
        try:
            key_bytes = bytes.fromhex(key_input)  # Converte chave hex para bytes
            text = ui.input_text_area("Texto")    # Entrada do texto

            # Validação do tamanho da chave
            if option == "DES" and len(key_bytes) != 8:
                ui.display_error("A chave do DES deve ter 8 bytes.")
            elif option == "AES" and len(key_bytes) not in (16, 24, 32):
                ui.display_error("A chave do AES deve ter 16, 24 ou 32 bytes.")
            else:
                # Criptografia ou descriptografia conforme seleção do usuário
                if mode == "Criptografar":
                    result = encrypt_des(text, key_bytes) if option == "DES" else encrypt_aes(text, key_bytes)
                    ui.display_result(result, "Texto criptografado")
                else:
                    try:
                        result = decrypt_des(text, key_bytes) if option == "DES" else decrypt_aes(text, key_bytes)
                        ui.display_result(result, "Texto original")
                    except Exception as e:
                        ui.display_error("Erro na descriptografia: " + str(e))
        except ValueError:
            ui.display_error("A chave precisa estar em hexadecimal válido.")

# Lógica para algoritmo assimétrico (RSA)
elif option == "RSA":
    st.subheader("Gerar ou colar chaves RSA")

    # Gera chaves RSA se não existirem na sessão
    if "rsa_private" not in st.session_state:
        private_key, public_key = generate_rsa_keys()
        st.session_state.rsa_private = private_key.decode()
        st.session_state.rsa_public = public_key.decode()

    # Campos para entrada das chaves e texto
    public_key = ui.input_text_area("Chave Pública", height=150)
    private_key = ui.input_text_area("Chave Privada", height=250)
    text = ui.input_text_area("Texto")

    # Criptografia ou descriptografia conforme seleção do usuário
    if mode == "Criptografar":
        try:
            result = encrypt_rsa(text, public_key.encode())
            ui.display_result(result, "Texto criptografado")
        except Exception as e:
            ui.display_error("Erro na criptografia: " + str(e))
    else:
        try:
            result = decrypt_rsa(text, private_key.encode())
            ui.display_result(result, "Texto original")
        except Exception as e:
            ui.display_error("Erro na descriptografia: " + str(e))