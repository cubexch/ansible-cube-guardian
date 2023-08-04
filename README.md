## 1. Ansible Collection - cubexch.guardian

- [1. Ansible Collection - cubexch.guardian](#1-ansible-collection---cubexchguardian)
- [2. Requirements](#2-requirements)
  - [2.1. Guardian Server](#21-guardian-server)
  - [2.2. Hashicorp Vault Cluster](#22-hashicorp-vault-cluster)
  - [2.3. Public Guardian List Approval](#23-public-guardian-list-approval)
- [3. Hashicorp Vault _**TESTING**_](#3-hashicorp-vault-testing)
  - [3.1. Install Hashicorp Vault for _**TESTING**_](#31-install-hashicorp-vault-for-testing)
  - [3.2. Start Hashicorp Vault for _**TESTING**_](#32-start-hashicorp-vault-for-testing)
- [4. Conventions](#4-conventions)
- [5. Ansible Configuration](#5-ansible-configuration)
  - [5.1. Configure your virtual environment.](#51-configure-your-virtual-environment)
  - [5.2. Create the `.ansible-vault.key` file to contain your Ansible Vault password.](#52-create-the-ansible-vaultkey-file-to-contain-your-ansible-vault-password)
  - [5.3. Create `ansible.cfg` and set the `vault_password_file` to `.ansible-vault.key`](#53-create-ansiblecfg-and-set-the-vault_password_file-to-ansible-vaultkey)
  - [5.4. Install pip \& Ansible Galaxy requirements inside `cube-guardian` virtual environment.](#54-install-pip--ansible-galaxy-requirements-inside-cube-guardian-virtual-environment)
- [6. Setup Hashicorp Vault Cluster](#6-setup-hashicorp-vault-cluster)
  - [6.1. Inventory Setup](#61-inventory-setup)
    - [6.1.1. Create an Ansible inventory for your Hashicorp Vault Cluster](#611-create-an-ansible-inventory-for-your-hashicorp-vault-cluster)
    - [6.1.2. Optional - Set `ansible_user` and `ansible_ssh_private_key_file` in `group_vars` under the `all` group](#612-optional---set-ansible_user-and-ansible_ssh_private_key_file-in-group_vars-under-the-all-group)
    - [6.1.3. Verify Connectivity to Vault Cluster Nodes](#613-verify-connectivity-to-vault-cluster-nodes)
    - [6.1.4. Create `group_vars` for the `geerlingguy.swap` role under the `all` group](#614-create-group_vars-for-the-geerlingguyswap-role-under-the-all-group)
    - [6.1.5. Create `group_vars` for the `cubexch.guardian.hashicorp_vault_cluster` role under the `example_hashicorp_vault_cluster` group:](#615-create-group_vars-for-the-cubexchguardianhashicorp_vault_cluster-role-under-the-example_hashicorp_vault_cluster-group)
  - [6.2. Self-Signed Certificates for Vault Cluster Nodes](#62-self-signed-certificates-for-vault-cluster-nodes)
    - [6.2.1. Create Ansible Playbook to Generate Self-Signed Certificates for Vault Cluster Nodes](#621-create-ansible-playbook-to-generate-self-signed-certificates-for-vault-cluster-nodes)
    - [6.2.2. SENSITIVE: Generate Self-Signed Certificates](#622-sensitive-generate-self-signed-certificates)
    - [6.2.3. SENSITIVE: Encrypt Private Keys for Self-Signed Certs](#623-sensitive-encrypt-private-keys-for-self-signed-certs)
  - [6.3. Deploy Vault Cluster](#63-deploy-vault-cluster)
    - [6.3.1. Create Ansible Playbook to Deploy Hashicorp Vault Cluster](#631-create-ansible-playbook-to-deploy-hashicorp-vault-cluster)
    - [6.3.2. Deploy Hashicorp Vault Cluster](#632-deploy-hashicorp-vault-cluster)
    - [6.3.3. SENSITIVE: Encrypt Vault Init Data](#633-sensitive-encrypt-vault-init-data)
- [7. Guardian Configuration](#7-guardian-configuration)
  - [7.1. Create an Ansible inventory for your Guardian node.](#71-create-an-ansible-inventory-for-your-guardian-node)
  - [7.2. Verify Connectivity to Guardian Node with Ansible](#72-verify-connectivity-to-guardian-node-with-ansible)
  - [7.3. OPTIONAL: Create `host_vars` for the `geerlingguy.certbot` role:](#73-optional-create-host_vars-for-the-geerlingguycertbot-role)
  - [7.4. Create `host_vars` for your non-sensitive Guardian Vault Configuration](#74-create-host_vars-for-your-non-sensitive-guardian-vault-configuration)
  - [7.5. TODO - Unused??](#75-todo---unused)
  - [7.6. SENSITIVE: Create `host_vars` for sensitive Guardian Node Configuration](#76-sensitive-create-host_vars-for-sensitive-guardian-node-configuration)
  - [7.7. SENSITIVE: Encrypt `host_vars` for sensitive Guardian Node Configuration with Ansible Vault](#77-sensitive-encrypt-host_vars-for-sensitive-guardian-node-configuration-with-ansible-vault)
  - [7.8. Create `host_vars` for your non-sensitive Guardian Node Configuration](#78-create-host_vars-for-your-non-sensitive-guardian-node-configuration)
  - [7.9. Create an Ansible playbook to deploy](#79-create-an-ansible-playbook-to-deploy)
  - [7.10. Run the playbook to configure the Guardian Node](#710-run-the-playbook-to-configure-the-guardian-node)
  - [7.11. Verify inbound connectivity to your Guardian Node](#711-verify-inbound-connectivity-to-your-guardian-node)
  - [7.12. Verify your Guardian Certificate has the expected CN](#712-verify-your-guardian-certificate-has-the-expected-cn)
- [8. SENSITIVE: Ensure All Sensitive Information Encrypted with Ansible Vault](#8-sensitive-ensure-all-sensitive-information-encrypted-with-ansible-vault)
- [9. FAQ](#9-faq)
  - [9.1. How can I check the status of the Guardian service?](#91-how-can-i-check-the-status-of-the-guardian-service)
  - [9.2. How can I check the deployed configuration?](#92-how-can-i-check-the-deployed-configuration)
  - [9.3. How can I view the Guardian logs?](#93-how-can-i-view-the-guardian-logs)
  - [9.4. Example Log Messages](#94-example-log-messages)
    - [9.4.1. Successful Guardian Connection to Hashicorp Vault](#941-successful-guardian-connection-to-hashicorp-vault)
    - [9.4.2. Successful Guardian Key Initialization](#942-successful-guardian-key-initialization)
    - [9.4.3. Successful Guardian Peer Connection](#943-successful-guardian-peer-connection)
    - [9.4.4. Successful User Key Generation](#944-successful-user-key-generation)
    - [9.4.5. Failed Peer Connection - Received Invalid TLS Certificate Name](#945-failed-peer-connection---received-invalid-tls-certificate-name)
    - [9.4.6. Other Errors](#946-other-errors)

## 2. Requirements

### 2.1. Guardian Server

- 1x Guardian Server
  - Minimum Recommended Spec:
    - OS: Ubuntu 20.04
    - CPU: 24 core
    - MEM: 64gb
    - DISK: 1TB NVME SSD
    - NET:
      - Guardian `<->` Guardian: 1Gbps internet connectivity
      - Guardian `->` Hashicorp Vault: 1Gbps internal connectivity
    - Public DNS and SSL/TLS certificates (guardian to guardian)

### 2.2. Hashicorp Vault Cluster

- 3x Hashicorp Vault Cluster Nodes
  - Recommend physical servers in accordance with the `Large` cluster specifications if possible, or single tenant virtual machines at a minimum.
  - REF:
    - [Hashicorp Vault - System Requirements](https://developer.hashicorp.com/vault/tutorials/day-one-raft/raft-reference-architecture#system-requirements)
    - [Hashicorp Vault - Production Hardening](https://developer.hashicorp.com/vault/tutorials/day-one-raft/production-hardening)
- The Hashicorp Vault cluster should be initialized in accordance with your standard practices.
- An Authentication token is not required to _**create**_ the Hashicorp Vault configuration files (\*.hcl)
- An Authentication token is required to _**deploy**_ the Hashicorp Vault configurations _**and**_ to retrieve the AppRole ID and SecretID credentials used by the Guardian to authenticate to the Vault cluster.

### 2.3. Public Guardian List Approval

Cube Exchange will add new Guardians to the public list after they have been reviewed and approved. Guardians will not communicate with each other if they have not been added to the approved list.

View the public list of Guardians at `public_guardian_list` in [roles/guardian/defaults/main.yml](roles/guardian/defaults/main.yml)

## 3. Hashicorp Vault _**TESTING**_

If you would like to setup a _**DEV**_ instance of Hashicorp Vault to test the Guardian deployment process, you can install Hashicorp Vault and run it with the `-dev-tls` option to create an in-memory instance.

### 3.1. Install Hashicorp Vault for _**TESTING**_

```bash
# ssh to your Guardian Server

# Add Hashicorp Vault apt repo
# REF: https://www.hashicorp.com/official-packaging-guide
sudo apt update && sudo apt install gpg
wget -O- https://apt.releases.hashicorp.com/gpg | sudo gpg --dearmor -o /usr/share/keyrings/hashicorp-archive-keyring.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] https://apt.releases.hashicorp.com $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/hashicorp.list

# Install Vault
sudo apt update && sudo apt install vault
```

### 3.2. Start Hashicorp Vault for _**TESTING**_

```bash
# Start vault in DEV-TLS mode
vault server -dev-tls

### Example Output
==> Vault server configuration:

Administrative Namespace:
             Api Address: https://127.0.0.1:8200
                     Cgo: disabled
         Cluster Address: https://127.0.0.1:8201
   Environment Variables: DBUS_SESSION_BUS_ADDRESS, GODEBUG, GOTRACEBACK, HOME, LANG, LESSCLOSE, LESSOPEN, LOGNAME, LS_COLORS, MOTD_SHOWN, PATH, PWD, SHELL, SHLVL, SSH_CLIENT, SSH_CONNECTION, SSH_TTY, TERM, USER, XDG_DATA_DIRS, XDG_RUNTIME_DIR, XDG_SESSION_CLASS, XDG_SESSION_ID, XDG_SESSION_TYPE, _
              Go Version: go1.20.5
              Listener 1: tcp (addr: "127.0.0.1:8200", cluster address: "127.0.0.1:8201", max_request_duration: "1m30s", max_request_size: "33554432", tls: "enabled")
               Log Level:
                   Mlock: supported: true, enabled: false
           Recovery Mode: false
                 Storage: inmem
                 Version: Vault v1.14.1, built 2023-07-21T10:15:14Z
             Version Sha: bf23fe8636b04d554c0fa35a756c75c2f59026c0

==> Vault server started! Log data will stream in below:

...
...
...

WARNING! dev mode is enabled! In this mode, Vault runs entirely in-memory
and starts unsealed with a single unseal key. The root token is already
authenticated to the CLI, so you can immediately begin using Vault.

You may need to set the following environment variables:

    $ export VAULT_ADDR='https://127.0.0.1:8200'
    $ export VAULT_CACERT='/tmp/vault-tls4054009470/vault-ca.pem'


The unseal key and root token are displayed below in case you want to
seal/unseal the Vault or re-authenticate.

Unseal Key: MY_UNSEAL_KEY
Root Token: hvs.MY_ROOT_TOKEN_VALUE

Development mode should NOT be used in production installations!
```

The key pieces of information from the output are the `VAULT_ADDR`, `VAULT_CACERT`, and `Root Token`. You can use these values to update their corresponding ansible inventory variables in the following steps.

- `VAULT_ADDR='https://127.0.0.1:8200'` ->
- `VAULT_CACERT='/tmp/vault-tls4054009470/vault-ca.pem'` ->
- `Root Token: hvs.MY_ROOT_TOKEN_VALUE` ->

## 4. Conventions

- Files containing sensitive variables have a `.ansible_vault.yml` suffix to indicate they contain sensitive variable definitions and should be encrypted with Ansible Vault.

  - You can use the following commands to easily encrypt/decrypt all sensitive files

    ```bash
    for f in $(find inventory/ -type f -name "*.ansible_vault.yml") ;do ansible-vault decrypt $f ;done
    for f in $(find inventory/ -type f -name "*.ansible_vault.yml") ;do ansible-vault encrypt $f ;done
    ```

- Variables containing sensitive information have a `_vault` suffix to indicate that they should be encrypted with Ansible Vault

  - This allows you to easily search for where the base variable is used even when the file containing the sensitive variable definition is encrypted.

    ```bash
    for f in $(find inventory/ -type f -name "*.ansible_vault.yml") ;do ansible-vault encrypt $f ;done
    Encryption successful
    Encryption successful

    grep -R guardian_access_token .
    ./inventory/host_vars/example-guard-1/guardian.yml:guardian_access_token: "{{ guardian_access_token_vault }}"

    for f in $(find inventory/ -type f -name "*.ansible_vault.yml") ;do ansible-vault decrypt $f ;done
    Decryption successful
    Decryption successful

    grep -R guardian_access_token .
    ./inventory/host_vars/example-guard-1/guardian.ansible_vault.yml:guardian_access_token_vault: "my_guardian_access_token"
    ./inventory/host_vars/example-guard-1/guardian.yml:guardian_access_token: "{{ guardian_access_token_vault }}"
    ```

## 5. Ansible Configuration

> While any Python 3.8+ version should be sufficient for running this collection with Ansible, only Python 3.8.10 has been verified.
>
> As an option, you can use Python 3.8.10 within a `pyenv` virtual environment. Please refer to the [PyEnv Installation Guide](https://github.com/pyenv/pyenv#installation) for detailed instructions.

### 5.1. Configure your virtual environment.

1.  If you'd like to use `pyenv`

    ```bash
    # Ubuntu pyenv pre-reqs
    sudo apt update
    sudo apt install build-essential libssl-dev zlib1g-dev libbz2-dev libreadline-dev libsqlite3-dev curl libncursesw5-dev xz-utils tk-dev libxml2-dev libxmlsec1-dev libffi-dev liblzma-dev

    # Get pyenv with automatic installer
    curl https://pyenv.run | bash

    # Activate pyenv according to installer output
    export PYENV_ROOT="$HOME/.pyenv"
    command -v pyenv >/dev/null || export PATH="$PYENV_ROOT/bin:$PATH"
    eval "$(pyenv init -)"

    # Setup pyenv and pyenv virtual environment
    pyenv install 3.8.10
    pyenv virtualenv 3.8.10 cube-guardian
    pyenv activate 3.8.10/envs/cube-guardian
    cd example
    ```

2.  If you'd like to just use a Python Virtual Environment

    ```bash
    python3 -m venv .venv
    source .venv/bin/activate
    cd example
    ```

### 5.2. Create the `.ansible-vault.key` file to contain your Ansible Vault password.

`.ansible-vault.key`

```text
my_secret_ansible_vault_password
```

### 5.3. Create `ansible.cfg` and set the `vault_password_file` to `.ansible-vault.key`

`ansible.cfg`

```ini
[defaults]
roles_path = .ansible-galaxy-roles:./roles
collections_paths = .ansible-galaxy-collections
vault_password_file = .ansible-vault.key
inventory = ./inventory/hosts-example.ini

[ssh_connection]
retries = 3
pipelining = true
```

### 5.4. Install pip & Ansible Galaxy requirements inside `cube-guardian` virtual environment.

```bash
pip install -r requirements.txt
ansible-galaxy install -r requirements.yml --force
```

## 6. Setup Hashicorp Vault Cluster

### 6.1. Inventory Setup

#### 6.1.1. Create an Ansible inventory for your Hashicorp Vault Cluster

`inventory/hosts-example.ini`

```ini
[all]
example-vault-1  ansible_host=127.0.0.1
example-vault-2  ansible_host=127.0.0.2
example-vault-3  ansible_host=127.0.0.3

[example_hashicorp_vault_cluster]
example-vault-[1:3]
```

#### 6.1.2. Optional - Set `ansible_user` and `ansible_ssh_private_key_file` in `group_vars` under the `all` group

`inventory/group_vars/all/all.yml`

```yml
ansible_user: ansible
ansible_ssh_private_key_file: ~/.ssh/id_ed25519
```

#### 6.1.3. Verify Connectivity to Vault Cluster Nodes

```bash
ansible example_hashicorp_vault_cluster -i inventory/hosts-example.ini -m ping --one-line
```

#### 6.1.4. Create `group_vars` for the `geerlingguy.swap` role under the `all` group

> It is strongly recommended to disable swap on both the Guardian _**and**_ all of your Vault Cluster Nodes

`inventory/group_vars/all/geerlingguy.swap.yml`

```yml
swap_file_state: absent
```

#### 6.1.5. Create `group_vars` for the `cubexch.guardian.hashicorp_vault_cluster` role under the `example_hashicorp_vault_cluster` group:

`inventory/group_vars/example_hashicorp_vault_cluster/cubexch.guardian.hashicorp_vault_cluster.yml`

```yml
### Option to create /etc/hosts entries ###
# Option to create /etc/hosts entries for each cluster member
create_etc_hosts_entries: true

### Required Inventory Variables when creating /etc/hosts entries ###
# Select an interface to get an IP address from when creating /etc/hosts entries
#
## Select the default interface detected by ansible
# hashicorp_vault_interface_api_interface: "{{ ansible_default_ipv4.interface }}"
## Or specify an interface name
hashicorp_vault_interface_api_interface: 'bond0'
# hashicorp_vault_interface_api_ip: "{{ hostvars[inventory_hostname]['ansible_' ~ hashicorp_vault_interface_api_interface]['ipv4']['address'] }}"
###########################################

# Inventory Group Name for your Hashicorp Vault Cluster
hashicorp_vault_cluster_group_name: 'example_hashicorp_vault_cluster'
# FQDN suffix to use for each host (i.e. example-vault-1.vault.example.com)
fqdn_suffix: 'hashicorp-vault.testing.cube.exchange'
hashicorp_vault_cluster_name: 'example-guardian-vault'

# Port used for API communications to the cluster
hashicorp_vault_cluster_port_api: 8200
# Port used for internal cluster node-to-node communication
hashicorp_vault_cluster_port_cluster: 8201

# Optional: Open Firewall Rules with iptables
open_iptables: true
hashicorp_vault_cluster_port_api_source_network: '127.0.0.0/24'
hashicorp_vault_cluster_port_cluster_source_network: '127.0.0.0/24'

self_signed_certs_generate: true
self_signed_certs_local_dir: '{{ inventory_dir }}/hashicorp-vault-certs'

hashicorp_vault_init_data_local_dir: '{{ inventory_dir }}/hashicorp-vault-init'
```

### 6.2. Self-Signed Certificates for Vault Cluster Nodes

#### 6.2.1. Create Ansible Playbook to Generate Self-Signed Certificates for Vault Cluster Nodes

`playbooks/generate_self_signed_certs.yml`

```yml
- name: Generate Self-Signed Certificates Locally
  hosts: example_hashicorp_vault_cluster
  gather_facts: false
  become: false
  tasks:
    - name: Create self_signed_certs_local_dir
      delegate_to: localhost
      ansible.builtin.file:
        dest: '{{ self_signed_certs_local_dir }}'
        state: directory
        mode: 'u+rw,g+r,o=-'
      tags:
        - generate_self_signed_certs

    - name: Generate Self Signed Certs
      delegate_to: localhost
      ansible.builtin.command:
        cmd: '{{ playbook_dir }}/files/generate_self_signed_certs.sh {{ fqdn_suffix }} {{ item }} {{ self_signed_certs_local_dir }}'
        chdir: '{{ self_signed_certs_local_dir }}'
      with_items:
        - '{{ groups[hashicorp_vault_cluster_group_name] }}'
      tags:
        - generate_self_signed_certs
```

#### 6.2.2. SENSITIVE: Generate Self-Signed Certificates

```bash
ansible-playbook -i ./inventory/hosts-example.ini playbooks/generate_self_signed_certs.yml --diff -v
```

#### 6.2.3. SENSITIVE: Encrypt Private Keys for Self-Signed Certs

```bash
for f in $(find . -type f -name "*.private.key") ;do echo Encrypting $f ;ansible-vault encrypt $f ;done
```

### 6.3. Deploy Vault Cluster

#### 6.3.1. Create Ansible Playbook to Deploy Hashicorp Vault Cluster

`playbooks/deploy_hashicorp_vault.yml`

```yml
- name: Deploy Hashicorp Vault Cluster
  hosts: example_hashicorp_vault_cluster
  gather_facts: false
  become: true
  become_user: root
  roles:
    - geerlingguy.swap
    - cubexch.guardian.hashicorp_vault_cluster
```

#### 6.3.2. Deploy Hashicorp Vault Cluster

```bash
ansible-playbook -i ./inventory/hosts-example.ini playbooks/deploy_hashicorp_vault.yml --diff -v
```

#### 6.3.3. SENSITIVE: Encrypt Vault Init Data

The `hashicorp_vault_cluster` role initializes the Vault Cluster and saves the secret keys and root token to the default location of `{{ inventory_dir }}/hashicorp-vault-init`.

You can override the default location to store this sensitive information by changing `hashicorp_vault_init_data_local_dir` in `inventory/group_vars/example_hashicorp_vault_cluster/cubexch.guardian.hashicorp_vault_cluster.yml`.

> Ensure this sensitive information is encrypted wherever it is stored.

```bash
for f in $(find . -type f -name "*.private.key") ;do echo Encrypting $f ;ansible-vault encrypt $f ;done
for f in $(find . -type f -name "*.ansible_vault.yml") ;do echo Encrypting $f ;ansible-vault encrypt $f ;done
```

## 7. Guardian Configuration

### 7.1. Create an Ansible inventory for your Guardian node.

`inventory/hosts-example.ini`

```ini
[all]
example-guard-1  ansible_host=127.0.0.11

[example_guardian_group]
example-guard-1
```

### 7.2. Verify Connectivity to Guardian Node with Ansible

```bash
ansible example_guardian_group -i inventory/hosts-example.ini -m ping --one-line
```

### 7.3. OPTIONAL: Create `host_vars` for the `geerlingguy.certbot` role:

Unless you are providing your own public SSL certificates, use the recommended configurations below:

> NOTE:
>
> - Certbot's standalone verification process will start a temporary http web server on the guardian to handle the Let's Encrypt challenge process.
> - In order for the challenge process to work, Let's Encrypt will try to access the FQDN on HTTP port 80.
> - You will need to ensure DNS has been configured for your Guardian's FQDN, and that firewall rules are opened for HTTP port 80.

`inventory/host_vars/example-guard-1/geerlingguy_certbot.yml`

```yml
# Update the admin email address used to create the ACME certificate account for certbot
certbot_admin_email: my_name@my_email_address.com

# Recommended settings listed below, please consult the geerlingguy.certbot role documentation before changing
# REF: https://github.com/geerlingguy/ansible-role-certbot
certbot_install_method: package
certbot_auto_renew: true
certbot_auto_renew_user: 'root'
certbot_auto_renew_hour: '{{ 24 | random(seed=guardian_instance.public_fqdn) }}'
certbot_auto_renew_minute: '{{ 60 | random(seed=guardian_instance.public_fqdn) }}'
certbot_auto_renew_options: '--quiet'
certbot_create_if_missing: true
certbot_create_method: standalone
certbot_certs:
  - domains:
      - '{{ guardian_instance.public_fqdn }}'
```

### 7.4. Create `host_vars` for your non-sensitive Guardian Vault Configuration

### 7.5. TODO - Unused??

`inventory/host_vars/example-guard-1/guardian_vault_config.yml`

```yml
# The guardian_vault_config role will generate *.hcl config files in the cube_vault_configs_dir
cube_vault_configs_dir: /opt/example-guard-1-vault-configs

vault_cluster_fqdn: 'hashicorp-vault.testing.cube.exchange'
self_signed_certs_local_dir: '{{ inventory_dir }}/hashicorp-vault-certs'
self_signed_cert_files:
  ca_cert: '{{ vault_cluster_fqdn }}.ca.cert.pem'

# Update the Vault URL to point to your Vault Cluster
# vault_url: 'https://127.0.0.1:8200'
vault_url: 'https://example-vault-1.hashicorp-vault.testing.cube.exchange:8200'

# Update the guardian_hostname to match the hostname set in inventory (i.e. inventory_hostname)
# Update the guardian_id to match the Guardian ID number assigned to you by Cube.Exchange
guardian_instances:
  - guardian_hostname: example-guardian-1
    guardian_id: 000

# It is strongly recommended to limit the CIDR's allowed to use the AppRole and Token created in Vault
# Update the guardian_secret_id_bound_cidrs and guardian_token_bound_cidrs to correspond with the internal IP used by the Guardian to talk to the Vault cluster
guardian_secret_id_bound_cidrs: '127.0.0.0/8'
guardian_token_bound_cidrs: '127.0.0.0/8'

# The guardian_vault_config role is able to handle all the Vault configuration required, but you must explicitly enable the actions below to allow it to connect to your cluster and make changes.
# Set vault_policy_deploy to false if you prefer to manually deploy the vault configurations
vault_policy_deploy: true
# Set vault_secrets_engine_deploy to false if you prefer to manually configure the Secrets Engine
vault_secrets_engine_deploy: true
# Set vault_approle_enable to false if you prefer to manually enable the AppRole authentication method
vault_approle_enable: true
# Set vault_approle_retrieve to false if you prefer to manually configure the AppRole ID and SecretsID
vault_approle_retrieve: true
```

### 7.6. SENSITIVE: Create `host_vars` for sensitive Guardian Node Configuration

`inventory/host_vars/example-guard-1/guardian.ansible_vault.yml`

```yml
# Use a secure password to control access to the Guardian Admin Interface
# i.e. openssl rand -hex 32
guardian_access_token_vault: 'my_guardian_access_token'
```

### 7.7. SENSITIVE: Encrypt `host_vars` for sensitive Guardian Node Configuration with Ansible Vault

```bash
for f in $(find . -type f -name "*.ansible_vault.yml") ;do echo Encrypting $f ;ansible-vault encrypt $f ;done
```

### 7.8. Create `host_vars` for your non-sensitive Guardian Node Configuration

`inventory/host_vars/example-guard-1/guardian.yml`

```yml
# Update the guardian_id to match the Guardian ID number assigned to you by Cube.Exchange
# Update the public_fqdn to match the publicly available DNS name where your Guardian can be reached.
guardian_instance:
  guardian_id: 204
  public_fqdn: example-guardian-1.testing.cube.exchange

vault_cluster_fqdn: 'hashicorp-vault.testing.cube.exchange'
self_signed_certs_local_dir: '{{ inventory_dir }}/hashicorp-vault-certs'
self_signed_cert_files:
  ca_cert: '{{ vault_cluster_fqdn }}.ca.cert.pem'

# Update the Vault URL and vault_tls_client_ca_* to match your Vault cluster
# - If the vault_tls_client_ca_filename already exists on the Guardian Node, you can specify vault_tls_client_ca_remote_source_dir and it will be copied to the Guardian Config location
# - If the vault_tls_client_ca_filename is located on your ansible control machine, you can specify vault_tls_client_ca_local_source_dir and it will be copied to the Guardian Node and saved in the Guardian Config location
guardian_key_storage:
  hashicorp_vault:
    vault_url: 'https://example-vault-1.hashicorp-vault.testing.cube.exchange:8200'
    vault_tls_client_ca_filename: '{{ self_signed_cert_files.ca_cert }}'
    vault_tls_client_ca_local_source_dir: '{{ inventory_dir }}/hashicorp-vault-certs'
    secret_mount_path: 'cube-guardian/guardian-{{ guardian_instance.guardian_id }}'
    approle_path_reader: '{{ guardian_dirs.config }}/vault.guardian.{{ inventory_hostname }}.reader.json'
    approle_path_writer: '{{ guardian_dirs.config }}/vault.guardian.{{ inventory_hostname }}.writer.json'
    approle_token_renew_seconds: 3600
    access_log_filename: 'access.json'

# The Guardian will be configured to listen on the default port of 9420 for node-to-node communication.
# You can use the settings below to use a different interface if needed:
guardian_listen_node_port: 20104

# If you would like Ansible to automatically create an iptables rule to allow the node-to-node traffic, set to guardian_listen_node_port_open_iptables: true
guardian_listen_node_port_open_iptables: true

# The Guardian will be configured to listen on the default port of 443 for end user web communication (i.e. emergency withdrawals).
# It is strongly recommended that you do not change the default port of 443 in order to ensure that end users don't have any challenges accessing the Guardian instance if needed.
guardian_listen_web_port: 443

# If you would like Ansible to automatically create an iptables rule to allow the web traffic, set to guardian_listen_node_port_open_iptables: true
guardian_listen_web_port_open_iptables: true

# The Guardian will be configured to listen on the default interface detected by ansible as the default listening IP.
# You can use the settings below to use a different interface for node-to-node or web communication if needed:
# # guardian_listen_node_interface: "{{ ansible_default_ipv4.interface }}"
# guardian_listen_node_interface: enp1s0
# guardian_listen_node_ip: "{{ hostvars[inventory_hostname]['ansible_' ~ guardian_listen_node_interface]['ipv4']['address'] }}"
# # guardian_listen_web_interface: "{{ ansible_default_ipv4.interface }}"
# guardian_listen_web_interface: enp1s0
# guardian_listen_web_ip: "{{ hostvars[inventory_hostname]['ansible_' ~ guardian_listen_web_interface]['ipv4']['address'] }}"

guardian_access_token: '{{ guardian_access_token_vault }}' # References value defined in guardian.ansible_vault.yml for clarity
```

### 7.9. Create an Ansible playbook to deploy

The list of roles can be adjusted if not all are desired.

- `geerlingguy.swap` disables swap
- `geerlingguy.certbot` installs certbot and creates the Guardian's TLS certificates
- `cubexch.guardian.guardian` installs and configures the Guardian service

`playbooks/deploy_guardian.yml`

```yml
- name: Deploy Guardian
  hosts: example_guardian_group
  gather_facts: false
  become: true
  become_user: root
  pre_tasks:
    - name: Gather OS Family
      ansible.builtin.setup:
        gather_subset:
          - os_family
  roles:
    - geerlingguy.swap
    - geerlingguy.certbot
    - cubexch.guardian.guardian_vault_config
    - cubexch.guardian.guardian
```

### 7.10. Run the playbook to configure the Guardian Node

```bash
ansible-playbook -i ./inventory/hosts-example.ini playbooks/deploy_guardian.yml --diff -v
```

If the Guardian service fails to start, please refer to [1.5. FAQ](#15-faq)

### 7.11. Verify inbound connectivity to your Guardian Node

```bash
nc -vz -w 10 example-guardian-1.testing.cube.exchange 20104
# Example Output
# Connection to example-guardian-1.testing.cube.exchange port 20104 [tcp/*] succeeded!

nc -vz -w 10 example-guardian-1.testing.cube.exchange 443
# Example Output
# Connection to example-guardian-1.testing.cube.exchange port 443 [tcp/https] succeeded!
```

### 7.12. Verify your Guardian Certificate has the expected CN

```bash
openssl s_client -showcerts -connect example-guardian-1.testing.cube.exchange:443 </dev/null 2>/dev/null | grep s:CN
# Example Output
#  0 s:CN = example-guardian-1.testing.cube.exchange
```

- The `CN` of the certificate should match your entry in `public_guardian_list` at [roles/guardian/defaults/main.yml](roles/guardian/defaults/main.yml).
- The `public_guardian_list` entries correspond to the Guardian configuration toml entries

```bash
grep tls_name /opt/cube-guardian-204/config/production-204.toml -C 3

[[nodes.guardians]]
id = 201
addr = "guardian-201.testing.cube.exchange:20101"
tls_name = "guardian-201.testing.cube.exchange"

[[nodes.guardians]]
id = 202
addr = "guardian-202.testing.cube.exchange:20102"
tls_name = "guardian-202.testing.cube.exchange"

[[nodes.guardians]]
id = 203
addr = "guardian-203.testing.cube.exchange:20103"
tls_name = "guardian-203.testing.cube.exchange"

[[nodes.guardians]]
id = 204
addr = "example-guardian-1.testing.cube.exchange:20104"
tls_name = "example-guardian-1.testing.cube.exchange"

[[nodes.guardians]]
id = 205
addr = "example-guardian-2.testing.cube.exchange:20105"
tls_name = "example-guardian-2.testing.cube.exchange"
```

## 8. SENSITIVE: Ensure All Sensitive Information Encrypted with Ansible Vault

```bash
for f in $(find . -type f -name "*.ansible_vault.yml") ;do echo Encrypting $f ;ansible-vault encrypt $f ;done
for f in $(find . -type f -name "*.private.key") ;do echo Encrypting $f ;ansible-vault encrypt $f ;done
```

## 9. FAQ

### 9.1. How can I check the status of the Guardian service?

The Ansible role deploys the Guardian service as a systemd service named `guardian-{{ your_guardian_id }}`.

```bash
root@example-guardian-1:~# systemctl status guardian-204.service
● guardian-204.service - "Cube Guardian - 204"
     Loaded: loaded (/etc/systemd/system/guardian-204.service; enabled; vendor preset: enabled)
     Active: active (running) since Tue 2023-08-01 14:46:19 UTC; 4h 59min ago
       Docs: https://docs.cube.exchange
   Main PID: 22284 (cube-aurum)
      Tasks: 18 (limit: 308638)
     Memory: 29.4M
     CGroup: /system.slice/guardian-204.service
             └─22284 /opt/cube-guardian-204/bin/current/cube-aurum

Aug 01 14:46:06 example-guardian-1 systemd[1]: Starting "Cube Guardian - 204"...
Aug 01 14:46:19 example-guardian-1 systemd[1]: Started "Cube Guardian - 204".



root@example-guardian-1:~# journalctl -n 100 -f -u guardian-204.service
-- Logs begin at Tue 2023-08-01 14:27:38 UTC. --
Aug 01 14:46:06 example-guardian-1 systemd[1]: Starting "Cube Guardian - 204"...
Aug 01 14:46:19 example-guardian-1 systemd[1]: Started "Cube Guardian - 204".
```

### 9.2. How can I check the deployed configuration?

- Guardian configuration files are stored in `/opt/cube-guardian-{{ your_guardian_id }}/config` by default
- Environment variables required by the Guardian service are in `guardian-{{ your_guardian_id }}.service.env`
- Guardian Application configurations are stored in `production-{{ your_guardian_id }}.toml`

```bash
root@example-guardian-1:~# ll /opt/cube-guardian-204/config/
total 48
drwxr-x--- 2 cube-guardian-204 cube-guardian-204 4096 Aug  1 14:46 ./
drwxr-x--- 4 cube-guardian-204 cube-guardian-204 4096 Aug  1 14:45 ../
-rw------- 1 cube-guardian-204 cube-guardian-204 1834 Aug  1 14:45 cert.pem
-rw------- 1 cube-guardian-204 cube-guardian-204 5584 Aug  1 14:45 fullchain.pem
-rw-r----- 1 cube-guardian-204 cube-guardian-204  200 Aug  1 14:45 guardian-204.service.env
-rw------- 1 cube-guardian-204 cube-guardian-204 1704 Aug  1 14:45 privkey.pem
-rw-r----- 1 cube-guardian-204 cube-guardian-204 1635 Aug  1 14:45 production-204.toml
-rw-r--r-- 1 cube-guardian-204 cube-guardian-204  810 Aug  1 15:52 public_shares.json
-rw-r----- 1 cube-guardian-204 cube-guardian-204  652 Aug  1 14:40 vault-ca.pem
-rw------- 1 cube-guardian-204 cube-guardian-204  114 Aug  1 14:44 vault.guardian.example-guardian-1.reader.json
-rw------- 1 cube-guardian-204 cube-guardian-204  114 Aug  1 14:45 vault.guardian.example-guardian-1.writer.json
```

### 9.3. How can I view the Guardian logs?

- Logs are written to `/var/log/cube-guardian-{{ your_guardian_id }}` by default.
- The `aurum.log.*` file is the primary application log.

```bash
root@example-guardian-1:~# ll /var/log/cube-guardian-204/
total 56
drwxr-x---  2 cube-guardian-204 cube-guardian-204  4096 Aug  1 14:46 ./
drwxrwxr-x 10 root              syslog             4096 Aug  1 14:45 ../
-rw-r--r--  1 cube-guardian-204 cube-guardian-204   683 Aug  1 15:52 access.json.2023-08-01
-rw-r--r--  1 cube-guardian-204 cube-guardian-204 37436 Aug  1 19:37 aurum.log.2023-08-01
-rw-r--r--  1 cube-guardian-204 cube-guardian-204     0 Aug  1 14:46 btc.log.2023-08-01
-rw-r--r--  1 cube-guardian-204 cube-guardian-204     0 Aug  1 14:46 cubenet.log.2023-08-01
-rw-r--r--  1 cube-guardian-204 cube-guardian-204     0 Aug  1 14:46 eth.log.2023-08-01
-rw-r--r--  1 cube-guardian-204 cube-guardian-204     0 Aug  1 14:46 metrics.log.2023-08-01
```

- You can tail the logs with the following command

```bash
tail -f /var/log/cube-guardian-204/aurum.log.$(date +'%F')
```

### 9.4. Example Log Messages

#### 9.4.1. Successful Guardian Connection to Hashicorp Vault

```bash
2023-08-01T14:46:07.023501Z  INFO cube_key_store::hashicorp_vault: login auth {"request_id":"20cd2583-7b8c-2ba2-53ef-1c12b6597344","auth":{"policies":["default","vault.guardian.204.writer.policy"],"token_policies":["default","vault.guardian.204.writer.policy"],"metadata":{"role_name":"cube-guardian-204.writer"}}}
2023-08-01T14:46:07.023757Z  INFO cube_key_store::hashicorp_vault: login auth {"request_id":"c758de74-d71d-05e0-1d87-20a67931711b","auth":{"policies":["default","vault.guardian.204.reader.policy"],"token_policies":["default","vault.guardian.204.reader.policy"],"metadata":{"role_name":"cube-guardian-204.reader"}}}
```

#### 9.4.2. Successful Guardian Key Initialization

> The initial key generation process could take some time to complete.

```bash
2023-08-01T14:41:56.121721Z  INFO cube_aurum::modules::manager: no paillier keys found at paillier_keys. generating...
2023-08-01T14:42:18.109109Z  INFO cube_aurum::modules::manager: precomputing local key tables...
```

#### 9.4.3. Successful Guardian Peer Connection

```bash
2023-08-01T14:46:20.511870Z  INFO cube_aurum::modules::guardian_nodes: accepting connection from (token:5 id:203 address:guardian-203.testing.cube.exchange:20103)
2023-08-01T14:46:20.511878Z  INFO cube_aurum::modules::guardian_nodes: connected to (token:5 id:203 address:guardian-203.testing.cube.exchange:20103)

2023-08-01T15:52:36.804541Z  INFO cube_aurum::modules::manager: guardian=201: connected
2023-08-01T15:52:38.255799Z  INFO cube_aurum::modules::manager: guardian=201: initialized keys
```

#### 9.4.4. Successful User Key Generation

```bash
2023-08-01T15:52:50.079367Z  INFO cube_aurum::modules::manager: job_id=56576470318841861 user_id=e480b799-0613-4fae-9ae1-3a49902d7d0e starting keygen
2023-08-01T15:52:50.079642Z  INFO cube_aurum::modules::manager: user_id=e480b799-0613-4fae-9ae1-3a49902d7d0e: calculated cipher key 9d9a5f9dae92c4742610b4e75a5d1f4c35d5ef6046534bf87e7e3e68e59d4b14
2023-08-01T15:52:50.706929Z  INFO cube_aurum::modules::manager: generated user_id=e480b799-0613-4fae-9ae1-3a49902d7d0e key_id=1690905169961379032 public_key=020950f146649432c0b91e71ba2b16d28ee4d28951ab899ab9b32b01f7d40e5e51
2023-08-01T15:52:51.822734Z  INFO cube_aurum::modules::manager: generated user_id=e480b799-0613-4fae-9ae1-3a49902d7d0e subaccount_id=1 key_id=1690905169961379000 public_key=028c8b2bb57aadf893dc3f5e96e3fbd40e7f42572762bc720408c8f1a3813c7ddc
```

#### 9.4.5. Failed Peer Connection - Received Invalid TLS Certificate Name

```bash
2023-08-01T17:42:08.668311Z  WARN rustls::msgs::handshake: Illegal SNI hostname received "147.75.84.211"
```

#### 9.4.6. Other Errors

- Generally logs tagged as `ERROR` represent a failure that should be investigated.
- Log messages for errors will typically include a descriptive message (and parameters if applicable) to indicate the source of the issue.
- Please reach out to Cube in our shared Slack channel if you run into any issues we haven't documented yet
