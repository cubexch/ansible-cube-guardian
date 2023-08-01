# 1. Ansible Collection - cubexch.guardian

- [1. Ansible Collection - cubexch.guardian](#1-ansible-collection---cubexchguardian)
  - [1.1. Requirements](#11-requirements)
    - [1.1.1. Guardian Server](#111-guardian-server)
    - [1.1.2. Hashicorp Vault Cluster](#112-hashicorp-vault-cluster)
    - [1.1.3. Public Guardian List Approval](#113-public-guardian-list-approval)
  - [1.2. Conventions](#12-conventions)
  - [1.3. Usage Guide](#13-usage-guide)
  - [1.4. Hashicorp Vault _**TESTING**_](#14-hashicorp-vault-testing)
    - [1.4.1. Install Hashicorp Vault for _**TESTING**_](#141-install-hashicorp-vault-for-testing)
    - [1.4.2. Start Hashicorp Vault for _**TESTING**_](#142-start-hashicorp-vault-for-testing)
    - [1.4.3. Configure your virtual environment.](#143-configure-your-virtual-environment)
    - [1.4.4. Install pip \& Ansible Galaxy requirements inside `cube-guardian` virtual environment.](#144-install-pip--ansible-galaxy-requirements-inside-cube-guardian-virtual-environment)
    - [1.4.5. Create the `.ansible-vault.key` file to contain your Ansible Vault password.](#145-create-the-ansible-vaultkey-file-to-contain-your-ansible-vault-password)
    - [1.4.6. Create `ansible.cfg` and set the `vault_password_file` to `.ansible-vault.key`](#146-create-ansiblecfg-and-set-the-vault_password_file-to-ansible-vaultkey)
    - [1.4.7. Create an Ansible inventory for your Guardian node.](#147-create-an-ansible-inventory-for-your-guardian-node)
    - [1.4.8. Create `host_vars` for the `geerlingguy.swap` role:](#148-create-host_vars-for-the-geerlingguyswap-role)
    - [1.4.9. OPTIONAL: Create `host_vars` for the `geerlingguy.certbot` role:](#149-optional-create-host_vars-for-the-geerlingguycertbot-role)
    - [1.4.10. Create `host_vars` for your sensitive Guardian Vault Configuration](#1410-create-host_vars-for-your-sensitive-guardian-vault-configuration)
    - [1.4.11. Create `host_vars` for your non-sensitive Guardian Vault Configuration](#1411-create-host_vars-for-your-non-sensitive-guardian-vault-configuration)
    - [1.4.12. Create `host_vars` for your sensitive Guardian Node Configuration](#1412-create-host_vars-for-your-sensitive-guardian-node-configuration)
    - [1.4.13. Let's just double check that we have all the ansible vault files encrypted:](#1413-lets-just-double-check-that-we-have-all-the-ansible-vault-files-encrypted)
    - [1.4.14. Create `host_vars` for your non-sensitive Guardian Node Configuration](#1414-create-host_vars-for-your-non-sensitive-guardian-node-configuration)
    - [1.4.15. Create an Ansible playbook to deploy](#1415-create-an-ansible-playbook-to-deploy)
    - [1.4.16. Run the playbook to configure the Guardian Node](#1416-run-the-playbook-to-configure-the-guardian-node)
    - [1.4.17. Verify inbound connectivity to your Guardian Node](#1417-verify-inbound-connectivity-to-your-guardian-node)
    - [1.4.18. Verify your Guardian Certificate has the expected CN](#1418-verify-your-guardian-certificate-has-the-expected-cn)
  - [1.5. FAQ](#15-faq)
    - [1.5.1. How can I check the status of the Guardian service?](#151-how-can-i-check-the-status-of-the-guardian-service)
    - [1.5.2. How can I check the deployed configuration?](#152-how-can-i-check-the-deployed-configuration)
    - [1.5.3. How can I view the Guardian logs?](#153-how-can-i-view-the-guardian-logs)
    - [1.5.4. Example Log Messages](#154-example-log-messages)
      - [1.5.4.1. Successful Guardian Connection to Hashicorp Vault](#1541-successful-guardian-connection-to-hashicorp-vault)
      - [1.5.4.2. Successful Guardian Key Initialization](#1542-successful-guardian-key-initialization)
      - [1.5.4.3. Successful Guardian Peer Connection](#1543-successful-guardian-peer-connection)
      - [1.5.4.4. Successful User Key Generation](#1544-successful-user-key-generation)
      - [1.5.4.5. Failed Peer Connection - Received Invalid TLS Certificate Name](#1545-failed-peer-connection---received-invalid-tls-certificate-name)
      - [1.5.4.6. Other Errors](#1546-other-errors)

## 1.1. Requirements

### 1.1.1. Guardian Server

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

### 1.1.2. Hashicorp Vault Cluster

- 3x Hashicorp Vault Cluster Nodes
  - Recommend physical servers in accordance with the `Large` cluster specifications if possible, or single tenant virtual machines at a minimum.
  - REF:
    - [Hashicorp Vault - System Requirements](https://developer.hashicorp.com/vault/tutorials/day-one-raft/raft-reference-architecture#system-requirements)
    - [Hashicorp Vault - Production Hardening](https://developer.hashicorp.com/vault/tutorials/day-one-raft/production-hardening)
- The Hashicorp Vault cluster should be initialized in accordance with your standard practices.
- An Authentication token is not required to _**create**_ the Hashicorp Vault configuration files (\*.hcl)
- An Authentication token is required to _**deploy**_ the Hashicorp Vault configurations _**and**_ to retrieve the AppRole ID and SecretID credentials used by the Guardian to authenticate to the Vault cluster.

### 1.1.3. Public Guardian List Approval

Cube Exchange will add new Guardians to the public list after they have been reviewed and approved. Guardians will not communicate with each other if they have not been added to the approved list.

View the public list of Guardians at `public_guardian_list` in [roles/guardian/defaults/main.yml](roles/guardian/defaults/main.yml)

## 1.2. Conventions

- Variables containing sensitive information have a `_vault` suffix to indicate that they should be encrypted with Ansible Vault

  - This allows you to easily search for where the base variable is used even when the file containing the sensitive variable definition is encrypted.

    ```bash
    for f in $(find . -type f -name "*.ansible_vault.yml") ;do ansible-vault encrypt $f ;done
    Encryption successful
    Encryption successful

    grep -R guardian_access_token .
    ./inventory/host_vars/example-guardian-1/guardian.yml:guardian_access_token: "{{ guardian_access_token_vault }}"

    for f in $(find . -type f -name "*.ansible_vault.yml") ;do ansible-vault decrypt $f ;done
    Decryption successful
    Decryption successful

    grep -R guardian_access_token .
    ./inventory/host_vars/example-guardian-1/guardian.ansible_vault.yml:guardian_access_token_vault: "my_guardian_access_token"
    ./inventory/host_vars/example-guardian-1/guardian.yml:guardian_access_token: "{{ guardian_access_token_vault }}"
    ```

- Files containing sensitive variables have a `.ansible_vault.yml` suffix to indicate they contain sensitive variable definitions and should be encrypted with Ansible Vault.

  - You can use the following commands to easily encrypt/decrypt all sensitive files

    ```bash
    for f in $(find . -type f -name "*.ansible_vault.yml") ;do ansible-vault decrypt $f ;done
    for f in $(find . -type f -name "*.ansible_vault.yml") ;do ansible-vault encrypt $f ;done
    ```

## 1.3. Usage Guide

> While any Python 3.8+ version should be sufficient for running this collection with Ansible, only Python 3.8.10 has been verified.
>
> As an option, you can use Python 3.8.10 within a `pyenv` virtual environment. Please refer to the [PyEnv Installation Guide](https://github.com/pyenv/pyenv#installation) for detailed instructions.

## 1.4. Hashicorp Vault _**TESTING**_

If you would like to setup a _**DEV**_ instance of Hashicorp Vault to test the Guardian deployment process, you can install Hashicorp Vault and run it with the `-dev-tls` option to create an in-memory instance.

### 1.4.1. Install Hashicorp Vault for _**TESTING**_

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

### 1.4.2. Start Hashicorp Vault for _**TESTING**_

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

Unseal Key: mn+seO/gqqIxh9naIr6rAkPkppEByJGceqo+jygijUo=
Root Token: hvs.TG34CH1tc3fwd5GwfWdTa3Ta

Development mode should NOT be used in production installations!
```

The key pieces of information from the output are the `VAULT_ADDR`, `VAULT_CACERT`, and `Root Token`. You can use these values to update their corresponding ansible inventory variables in the following steps.

- `VAULT_ADDR='https://127.0.0.1:8200'` ->
- `VAULT_CACERT='/tmp/vault-tls4054009470/vault-ca.pem'` ->
- `Root Token: hvs.TG34CH1tc3fwd5GwfWdTa3Ta` ->

### 1.4.3. Configure your virtual environment.

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

### 1.4.4. Install pip & Ansible Galaxy requirements inside `cube-guardian` virtual environment.

```bash
pip install -r requirements.txt
ansible-galaxy install -r requirements.yml --force
```

### 1.4.5. Create the `.ansible-vault.key` file to contain your Ansible Vault password.

`.ansible-vault.key`

```text
my_secret_ansible_vault_password
```

### 1.4.6. Create `ansible.cfg` and set the `vault_password_file` to `.ansible-vault.key`

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

### 1.4.7. Create an Ansible inventory for your Guardian node.

`inventory/hosts-example.ini`

```ini
[all]
example-guardian-1 ansible_host=145.40.68.61 ansible_user=ansible ansible_ssh_private_key_file=~/.ssh/id_ed25519

[example_guardian_group]
example-guardian-1
```

> Verify you can connect to the Guardian with Ansible

```bash
ansible all -i inventory/hosts-example.ini -m ping --one-line
example-guardian-1 | SUCCESS => {"ansible_facts": {"discovered_interpreter_python": "/usr/bin/python3"},"changed": false,"ping": "pong"}
```

### 1.4.8. Create `host_vars` for the `geerlingguy.swap` role:

> It is strongly recommended to disable swap on both the Guardian _**and**_ all of your Vault Cluster Nodes

`inventory/host_vars/example-guardian-1/geerlingguy_swap.yml`

```yml
swap_file_state: absent
```

### 1.4.9. OPTIONAL: Create `host_vars` for the `geerlingguy.certbot` role:

Unless you are providing your own public SSL certificates, use the recommended configurations below:

> NOTE: Certbot's standalone verification process will start an http web server on the server to handle the Let's Encrypt challenge process. In order for the challenge process to work, Let's Encrypt will try to access the FQDN on HTTP port 80. You will need to ensure DNS has been configured for your Guardian's FQDN, and that firewall rules are opened for HTTP port 80.

`inventory/host_vars/example-guardian-1/geerlingguy_certbot.yml`

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

### 1.4.10. Create `host_vars` for your sensitive Guardian Vault Configuration

`inventory/host_vars/example-guardian-1/guardian_vault_config.ansible_vault.yml`

```yml
# Update the Vault Auth Token to use for deploying configurations to your Vault cluster
cube_vault_auth_token_vault: 'hvs.my_vault_auth_token'
```

```bash
# Use ansible-vault to encrypt the contents of this sensitive configuration file
ansible-vault encrypt inventory/host_vars/example-guardian-1/guardian_vault_config.ansible_vault.yml
```

### 1.4.11. Create `host_vars` for your non-sensitive Guardian Vault Configuration

`inventory/host_vars/example-guardian-1/guardian_vault_config.yml`

```yml
# The guardian_vault_config role will generate *.hcl config files in the cube_vault_configs_dir
cube_vault_configs_dir: /opt/example-guardian-1-vault-configs

# Update the location where the Vault Cluster CA Cert has been deployed on the remote server
vault_ca_cert: '/tmp/vault-tls2489470720/vault-ca.pem'

# Update the Vault URL to point to your Vault Cluster
vault_url: 'https://127.0.0.1:8200'

# Update the guardian_hostname to match the hostname set in inventory (i.e. inventory_hostname)
# Update the guardian_id to match the Guardian ID number assigned to you by Cube.Exchange
guardian_instances:
  - guardian_hostname: example-guardian-1
    guardian_id: 204

# It is strongly recommended to limit the CIDR's allowed to use the AppRole and Token created in Vault
# Update the guardian_secret_id_bound_cidrs and guardian_token_bound_cidrs to correspond with the internal IP used by the Guardian to talk to the Vault cluster
guardian_secret_id_bound_cidrs: '127.0.0.0/24'
guardian_token_bound_cidrs: '127.0.0.0/24'

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

### 1.4.12. Create `host_vars` for your sensitive Guardian Node Configuration

`inventory/host_vars/example-guardian-1/guardian.ansible_vault.yml`

```yml
# Use a secure password to control access to the Guardian Admin Interface
# i.e. openssl rand -hex 32
guardian_access_token_vault: 'my_guardian_access_token'
```

```bash
# Use ansible-vault to encrypt the contents of this sensitive configuration file
ansible-vault encrypt inventory/host_vars/example-guardian-1/guardian.ansible_vault.yml
```

### 1.4.13. Let's just double check that we have all the ansible vault files encrypted:

```bash
for f in $(find inventory/ -type f -name "*.ansible_vault.yml") ;do ansible-vault encrypt $f ;done
```

### 1.4.14. Create `host_vars` for your non-sensitive Guardian Node Configuration

`inventory/host_vars/example-guardian-1/guardian.yml`

```yml
# Update the guardian_id to match the Guardian ID number assigned to you by Cube.Exchange
# Update the public_fqdn to match the publicly available DNS name where your Guardian can be reached.
guardian_instance:
  guardian_id: 204
  public_fqdn: example-guardian-1.testing.cube.exchange

# Update the Vault URL and vault_tls_client_ca_* to match your Vault cluster
# - If the vault_tls_client_ca_filename already exists on the Guardian Node, you can specify vault_tls_client_ca_remote_source_dir and it will be copied to the Guardian Config location
# - If the vault_tls_client_ca_filename is located on your ansible control machine, you can specify vault_tls_client_ca_local_source_dir and it will be copied to the Guardian Node and saved in the Guardian Config location
guardian_key_storage:
  hashicorp_vault:
    vault_url: 'https://127.0.0.1:8200'
    vault_tls_client_ca_filename: 'vault-ca.pem'
    vault_tls_client_ca_remote_source_dir: '/tmp/vault-tls2489470720'
    # vault_tls_client_ca_local_source_dir: "{{ inventory_dir }}/../.tmp/vault-certs"
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

guardian_approle_copy_remote_src: '{{ cube_vault_configs_dir }}' # References value defined in guardian_vault_config.yml for clarity
guardian_access_token: '{{ guardian_access_token_vault }}' # References value defined in guardian.ansible_vault.yml for clarity
```

### 1.4.15. Create an Ansible playbook to deploy

The list of roles can be adjusted if not all are desired.

- `cubexch.guardian.guardian_vault_config` generates and optionally deploys the required configurations to Hashicorp Vault
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
    - cubexch.guardian.guardian_vault_config
    - geerlingguy.certbot
    - cubexch.guardian.guardian
```

### 1.4.16. Run the playbook to configure the Guardian Node

```bash
ansible-playbook -i ./inventory/hosts-example.ini playbooks/deploy_guardian.yml --diff -v
```

### 1.4.17. Verify inbound connectivity to your Guardian Node

```bash
nc -vz -w 10 example-guardian-1.testing.cube.exchange 20104
Connection to example-guardian-1.testing.cube.exchange port 20104 [tcp/*] succeeded!

nc -vz -w 10 example-guardian-1.testing.cube.exchange 443
Connection to example-guardian-1.testing.cube.exchange port 443 [tcp/https] succeeded!
```

### 1.4.18. Verify your Guardian Certificate has the expected CN

```bash
openssl s_client -showcerts -connect example-guardian-1.testing.cube.exchange:443 </dev/null 2>/dev/null | grep s:CN
 0 s:CN = example-guardian-1.testing.cube.exchange
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

## 1.5. FAQ

### 1.5.1. How can I check the status of the Guardian service?

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

### 1.5.2. How can I check the deployed configuration?

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

### 1.5.3. How can I view the Guardian logs?

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

### 1.5.4. Example Log Messages

#### 1.5.4.1. Successful Guardian Connection to Hashicorp Vault

```bash
2023-08-01T14:46:07.023501Z  INFO cube_key_store::hashicorp_vault: login auth {"request_id":"20cd2583-7b8c-2ba2-53ef-1c12b6597344","auth":{"policies":["default","vault.guardian.204.writer.policy"],"token_policies":["default","vault.guardian.204.writer.policy"],"metadata":{"role_name":"cube-guardian-204.writer"}}}
2023-08-01T14:46:07.023757Z  INFO cube_key_store::hashicorp_vault: login auth {"request_id":"c758de74-d71d-05e0-1d87-20a67931711b","auth":{"policies":["default","vault.guardian.204.reader.policy"],"token_policies":["default","vault.guardian.204.reader.policy"],"metadata":{"role_name":"cube-guardian-204.reader"}}}
```

#### 1.5.4.2. Successful Guardian Key Initialization

> The initial key generation process could take some time to complete.

```bash
2023-08-01T14:41:56.121721Z  INFO cube_aurum::modules::manager: no paillier keys found at paillier_keys. generating...
2023-08-01T14:42:18.109109Z  INFO cube_aurum::modules::manager: precomputing local key tables...
```

#### 1.5.4.3. Successful Guardian Peer Connection

```bash
2023-08-01T14:46:20.511870Z  INFO cube_aurum::modules::guardian_nodes: accepting connection from (token:5 id:203 address:guardian-203.testing.cube.exchange:20103)
2023-08-01T14:46:20.511878Z  INFO cube_aurum::modules::guardian_nodes: connected to (token:5 id:203 address:guardian-203.testing.cube.exchange:20103)

2023-08-01T15:52:36.804541Z  INFO cube_aurum::modules::manager: guardian=201: connected
2023-08-01T15:52:38.255799Z  INFO cube_aurum::modules::manager: guardian=201: initialized keys
```

#### 1.5.4.4. Successful User Key Generation

```bash
2023-08-01T15:52:50.079367Z  INFO cube_aurum::modules::manager: job_id=56576470318841861 user_id=e480b799-0613-4fae-9ae1-3a49902d7d0e starting keygen
2023-08-01T15:52:50.079642Z  INFO cube_aurum::modules::manager: user_id=e480b799-0613-4fae-9ae1-3a49902d7d0e: calculated cipher key 9d9a5f9dae92c4742610b4e75a5d1f4c35d5ef6046534bf87e7e3e68e59d4b14
2023-08-01T15:52:50.706929Z  INFO cube_aurum::modules::manager: generated user_id=e480b799-0613-4fae-9ae1-3a49902d7d0e key_id=1690905169961379032 public_key=020950f146649432c0b91e71ba2b16d28ee4d28951ab899ab9b32b01f7d40e5e51
2023-08-01T15:52:51.822734Z  INFO cube_aurum::modules::manager: generated user_id=e480b799-0613-4fae-9ae1-3a49902d7d0e subaccount_id=1 key_id=1690905169961379000 public_key=028c8b2bb57aadf893dc3f5e96e3fbd40e7f42572762bc720408c8f1a3813c7ddc
```

#### 1.5.4.5. Failed Peer Connection - Received Invalid TLS Certificate Name

```bash
2023-08-01T17:42:08.668311Z  WARN rustls::msgs::handshake: Illegal SNI hostname received "147.75.84.211"
```

#### 1.5.4.6. Other Errors

- Generally logs tagged as `ERROR` represent a failure that should be investigated.
- Log messages for errors will typically include a descriptive message (and parameters if applicable) to indicate the source of the issue.
- Please reach out to Cube in our shared Slack channel if you run into any issues we haven't documented yet
