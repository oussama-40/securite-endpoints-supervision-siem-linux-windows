# Projet SIEM + EDR avec Wazuh sur AWS

## 📋 Introduction

Ce projet pratique met en place une plateforme complète de supervision et de protection sécurité combinant les approches **SIEM** (Security Information and Event Management) et **EDR** (Endpoint Detection and Response) avec **Wazuh**, déployée sur l'infrastructure **AWS Learner Lab**.

---

## 🏗️ Architecture

### Vue d'ensemble

L'environnement est composé de **3 instances EC2** configurées comme suit :

| Instance | Système d'exploitation | Rôle |
|----------|------------------------|------|
| **EC2-1** | Ubuntu 22.04 LTS | Wazuh All-in-One (Server + Indexer + Dashboard) |
| **EC2-2** | Ubuntu 22.04 LTS | Client Linux + Agent Wazuh |
| **EC2-3** | Windows Server | Client Windows + Agent Wazuh (+ Sysmon optionnel) |

### Flux réseau et ports requis

- **Agents → Wazuh Server** : `1514/TCP`
- **Enrôlement agent** : `1515/TCP`
- **Dashboard Web** : `443/HTTPS`
- **SSH Linux** : `22/TCP`
- **RDP Windows** : `3389/TCP`

---

## ☁️ Configuration AWS

### Spécifications des instances EC2

1. **Wazuh-Server**
   - Type : `t3.large`
   - Stockage : 30 GB
   - OS : Ubuntu 22.04 LTS

2. **Linux-Client**
   - Type : `t2.micro` ou `t3.micro`
   - OS : Ubuntu 22.04 LTS

3. **Windows-Client**
   - Type : `t2.medium` (minimum)
   - OS : Windows Server

### Groupes de sécurité

#### Wazuh-Server (Inbound)
- `22/tcp` depuis votre IP publique
- `443/tcp` depuis votre IP publique
- `1514/tcp` depuis les Security Groups des clients
- `1515/tcp` depuis les Security Groups des clients

#### Linux-Client
- `22/tcp` depuis votre IP publique

#### Windows-Client
- `3389/tcp` depuis votre IP publique

---

## 🚀 Installation

### 1. Installation du serveur Wazuh

Connectez-vous à l'instance **EC2-1** (Wazuh-Server) via SSH et exécutez :

```bash
# Mise à jour du système
sudo apt update && sudo apt -y upgrade

# Téléchargement du script d'installation
curl -so wazuh-install.sh https://packages.wazuh.com/4.7/wazuh-install.sh

# Installation complète (All-in-One)
sudo bash wazuh-install.sh -a
```

#### Vérification de l'installation

```bash
sudo systemctl status wazuh-manager
sudo systemctl status wazuh-indexer
sudo systemctl status wazuh-dashboard
```

Tous les services doivent être actifs et en cours d'exécution.

---

### 2. Installation de l'agent Linux

Connectez-vous à l'instance **EC2-2** (Linux-Client) via SSH et exécutez :

```bash
# Téléchargement de l'agent
wget https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.7.5-1_amd64.deb

# Installation avec configuration
sudo WAZUH_MANAGER='34.227.7.176' WAZUH_AGENT_NAME='Linux-Client' dpkg -i ./wazuh-agent_4.7.5-1_amd64.deb

# Activation et démarrage du service
sudo systemctl daemon-reload
sudo systemctl enable wazuh-agent
sudo systemctl start wazuh-agent
```

> **Note** : Remplacez `34.227.7.176` par l'adresse IP privée de votre serveur Wazuh.

---

### 3. Installation de l'agent Windows

Connectez-vous à l'instance **EC2-3** (Windows-Client) via RDP et exécutez dans PowerShell (en tant qu'administrateur) :

```powershell
# Téléchargement de l'agent
Invoke-WebRequest -Uri https://packages.wazuh.com/4.x/windows/wazuh-agent-4.7.5-1.msi -OutFile ${env:tmp}\wazuh-agent.msi

# Installation silencieuse avec configuration
msiexec.exe /i ${env:tmp}\wazuh-agent.msi /q WAZUH_MANAGER='3.88.161.18' WAZUH_AGENT_NAME='Client-Windows'
```

> **Note** : Remplacez `3.88.161.18` par l'adresse IP privée de votre serveur Wazuh.

#### Vérification

Ouvrez **Services Windows** et vérifiez que le service **Wazuh Agent** est en cours d'exécution.

---

## 🔍 Démonstrations SIEM + EDR

### Scénario 1 : Tentatives de connexion SSH échouées (Linux)

**Objectif** : Détecter les tentatives de force brute SSH

```bash
# Depuis un terminal local ou une autre machine
ssh fakeuser@34.227.7.176

# Répétez 5 à 10 fois avec un mauvais mot de passe
```

**Alertes attendues** :
- Type : `authentication failed / sshd`
- Source : `/var/log/auth.log`
- Détection : SIEM (analyse des logs)

---

### Scénario 2 : Élévation de privilèges (Linux)

**Objectif** : Surveiller l'utilisation de sudo

```bash
# Sur le client Linux
sudo su
```

**Alertes attendues** :
- Type : Commande `sudo` détectée
- Détection : EDR + SIEM (surveillance processus et logs système)

---

### Scénario 3 : Création d'utilisateur local (Windows)

**Objectif** : Détecter la création de comptes et modifications de groupes

```powershell
# Sur le client Windows (PowerShell en tant qu'administrateur)
net user labuser P@ssw0rd! /add
net localgroup administrators labuser /add
```

**Alertes attendues** :
- Type : `User created` / `Group membership changed`
- Event IDs Windows : 4720, 4732
- Détection : SIEM (logs Security Windows)

---

## 📊 Analyse : SIEM vs EDR

### Définitions et différences

| Type | Fonction principale | Exemples dans ce projet |
|------|---------------------|-------------------------|
| **SIEM** | Centralisation et corrélation des logs système | Logs SSH, Windows Security Events (4625, 4720, 4732) |
| **EDR** | Surveillance des endpoints en temps réel | Monitoring des processus, modifications systèmes, activités réseau |

### Approche Wazuh : Combinaison SIEM + EDR

Wazuh intègre les deux approches :
- **Aspect SIEM** : Collecte et corrélation des logs SSH, authentification Windows
- **Aspect EDR** : Surveillance en temps réel des processus, fichiers, et changements système

---

## 🔐 IAM & PAM : Détection des accès

### Identity and Access Management (IAM)

**Définition** : Gestion des identités et des accès utilisateurs

**Événements détectés** :
- Authentifications SSH (réussies/échouées)
- Connexions Windows (Event ID 4624, 4625)
- Création et suppression de comptes

### Privileged Access Management (PAM)

**Définition** : Gestion spécifique des accès privilégiés

**Événements détectés** :
- Commandes `sudo su` sur Linux
- Ajouts au groupe Administrateurs Windows
- Élévation de privilèges
- Activités administratives sensibles

---

## 🎯 Threat Hunting : Requêtes de détection

### Requête 1 : Force brute SSH

**Objectif** : Identifier les tentatives de force brute sur SSH

```sql
SELECT * FROM alerts 
WHERE rule.description LIKE '%ssh%failed%' 
AND agent.name = 'Linux-Client' 
AND timestamp >= NOW() - INTERVAL 1 HOUR 
GROUP BY source.ip 
HAVING COUNT(*) > 5;
```

**Détection** : Plus de 5 échecs d'authentification SSH depuis la même IP en 1 heure

---

### Requête 2 : Modifications de groupes Windows

**Objectif** : Surveiller les changements de groupes d'administration

```sql
SELECT timestamp, agent.name, rule.description, data.win.eventdata 
FROM alerts 
WHERE rule.id IN (60154, 60160, 60170) 
AND agent.name = 'Client-Windows' 
ORDER BY timestamp DESC 
LIMIT 10;
```

**Détection** : Modifications de groupes Windows (ajouts/suppressions de membres)

---

### Requête 3 : Activité suspecte hors heures normales

**Objectif** : Détecter les activités critiques en dehors des heures de travail

```sql
SELECT * FROM alerts 
WHERE (HOUR(timestamp) < 7 OR HOUR(timestamp) > 19) 
AND rule.level >= 10 
AND DATE(timestamp) = CURDATE() 
ORDER BY timestamp DESC;
```

**Détection** : Alertes critiques (niveau ≥ 10) entre 19h et 7h

---

## ✅ Conclusion

### Objectifs atteints

Ce projet a permis de :

1. ✅ Déployer une infrastructure Wazuh complète sur AWS
2. ✅ Installer et enrôler des agents sur Linux et Windows
3. ✅ Configurer les règles réseau et Security Groups AWS
4. ✅ Tester des scénarios réels d'attaque et de détection
5. ✅ Combiner les capacités SIEM et EDR avec Wazuh
6. ✅ Réaliser des requêtes de Threat Hunting

### Preuves et validation

Les captures d'écran associées au projet démontrent :
- La détection effective des événements de sécurité
- Le fonctionnement correct de la plateforme
- La corrélation entre SIEM et EDR

---

## 📝 Informations du projet
**Projet** : SIEM + EDR avec Wazuh sur AWS  
**Auteur** : ChatGPT Assistant  
**Date** : Janvier 2025

