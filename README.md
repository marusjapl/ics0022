# 🔐 Secure Password Manager

## 📌 Overview

This Python project is a **single-user, secure password manager**. It allows you to safely store and manage your usernames and passwords for websites or services. All credentials are saved locally in an encrypted vault and protected with a master password. Each time you add or update entries, the vault is securely updated and previous versions are backed up.

## 🚀 Features

-  Master password protected (hashed with bcrypt)  
-  AES-GCM encryption for all credentials  
-  Memory-safe: passwords are wiped from RAM after use  
-  Automatic vault backups in `vault_versions/`  
-  Simple CLI menu for managing credentials  
-  Secure file permissions (owner-only read/write)  


## 🛠 Installation

### Prerequisites

Ensure you have **Python 3.8 or newer installed. You can check with:

```sh
python3 --version
```

You also need to install the bcrypt and cryptography packages if not already installed:

```sh
pip install bcrypt cryptography
```


### Clone the Repository

```sh
git clone https://github.com/marusjapl/ics0022.git
cd password_manager.py
```

## ▶️ Usage

Run the code in your terminal:

```sh
python password_manager.py
```

## Initial Setup

The first time you run the script, it will prompt you to create a Master Password. 

```sh
python password_manager.py
```

## Routine Use

After setup, run the script and enter your Master Password to access the main menu:

```sh
python password_manager.py
```
