# 1. Ansible Collection - cube_exchange.guardian

- [1. Ansible Collection - cube\_exchange.guardian](#1-ansible-collection---cube_exchangeguardian)
  - [1.1. Requirements](#11-requirements)
  - [1.2. Usage Guide](#12-usage-guide)

## 1.1. Requirements

- 1x Guardian Server
  - Minimum Recommended Spec:
    - CPU: 24 core
    - MEM: 64gb
    - DISK: 1TB NVME SSD
    - NET:
      - Guardian `<->` Guardian: 1Gbps internet connectivity
      - Guardian `->` Hashicorp Vault: 1Gbps internal connectivity
    - Public DNS and SSL/TLS certificates (guardian to guardian)
- 3x Hashicorp Vault Cluster Nodes
  - Recommend physical servers in accordance with the `Large` cluster specifications if possible, or single tenant virtual machines at a minimum.
  - REF:
    - [Hashicorp Vault - System Requirements](https://developer.hashicorp.com/vault/tutorials/day-one-raft/raft-reference-architecture#system-requirements)
    - [Hashicorp Vault - Production Hardening](https://developer.hashicorp.com/vault/tutorials/day-one-raft/production-hardening)
  - The Hashicorp Vault cluster should be initialized in accordance with your standard practices.
  - An Authentication token is not required to _**create**_ the Hashicorp Vault configuration files (\*.hcl)
  - An Authentication token is required to _**deploy**_ the Hashicorp Vault configurations _**and**_ to retrieve the AppRole ID and SecretID credentials used by the Guardian to authenticate to the Vault cluster.

## 1.2. Usage Guide

> This guide uses Python 3.8.10 in a `pyenv` virtual environment. Please refer to the [PyEnv Installation Guide](https://github.com/pyenv/pyenv#installation) for installation instructions.

1. Configure `pyenv` virtual environment.

   ```bash
   pyenv install 3.8.10
   pyenv virtualenv 3.8.10 cube-guardian
   pyenv activate 3.8.10/envs/cube-guardian
   ```

2. Install pip & Ansible Galaxy requirements inside `cube-guardian` virtual environment.

   ```bash
   cd example
   pip install -r requirements.txt
   ansible-galaxy install -r requirements.yml
   ```

3. Create an Ansible inventory for your Guardian node.

   `example/inventory/hosts-example.ini`:

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

4. Create `host_vars` for the `geerlingguy.swap` role:

   > It is strongly recommended to disable swap on both the Guardian _**and**_ all of your Vault Cluster Nodes

   `inventory/host_vars/example-guardian-1/geerlingguy_swap.yml`:

   ```yml
   swap_file_state: absent
   ```

5. OPTIONAL: Create `host_vars` for the `geerlingguy.certbot` role:

   Unless you are providing your own public SSL certificates, use the recommended configurations below:

   `inventory/host_vars/example-guardian-1/geerlingguy_certbot.yml`:

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

6. Create the `.ansible-vault.key` file to contain your Ansible Vault password.

   `.ansible-vault.key`:

   ```text
   my_secret_ansible_vault_password
   ```

7. Create `ansible.cfg` and set the `vault_password_file` to `.ansible-vault.key`

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

8. Create `host_vars` for your sensitive Guardian Vault Configuration

   `inventory/host_vars/example-guardian-1/guardian_vault_config_vault.yml`:

   ```yml
   # Update the Vault Auth Token to use for deploying configurations to your Vault cluster
   cube_vault_auth_token_vault: 'hvs.my_vault_auth_token'
   ```

   ```bash
   # Use ansible-vault to encrypt the contents of this sensitive configuration file
   ansible-vault encrypt inventory/host_vars/example-guardian-1/guardian_vault_config_vault.yml
   ```

9. Create `host_vars` for your non-sensitive Guardian Vault Configuration

   `inventory/host_vars/example-guardian-1/guardian_vault_config.yml`:

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

10. Create `host_vars` for your sensitive Guardian Node Configuration

    `inventory/host_vars/example-guardian-1/guardian_vault.yml`:

    ```yml
    guardian_access_token_vault: 'your_secret_guardian_access_token'
    ```

    ```bash
    # Use ansible-vault to encrypt the contents of this sensitive configuration file
    ansible-vault encrypt inventory/host_vars/example-guardian-1/guardian_vault.yml
    ```

11. Let's just double check that we have all the ansible-vault files encrypted:

    ```bash
    for f in $(find inventory/ -type f -name "*_vault.yml") ;do ansible-vault encrypt $f ;done
    ```

12. Create `host_vars` for your non-sensitive Guardian Node Configuration

    `inventory/host_vars/example-guardian-1/guardian.yml`:

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

    # The Guardian will be configured to listen on the default port of 443 for end user web communication (i.e. emergency withdrawals).
    # It is strongly recommended that you do not change the default port of 443 in order to ensure that end users don't have any challenges accessing the Guardian instance if needed.
    guardian_listen_web_port: 443

    # The Guardian will be configured to listen on the default interface detected by ansible as the default listening IP.
    # You can use the settings below to use a different interface for node-to-node or web communication if needed:
    # # guardian_listen_node_interface: "{{ ansible_default_ipv4.interface }}"
    # guardian_listen_node_interface: enp1s0
    # guardian_listen_node_ip: "{{ hostvars[inventory_hostname]['ansible_' ~ guardian_listen_node_interface]['ipv4']['address'] }}"
    # # guardian_listen_web_interface: "{{ ansible_default_ipv4.interface }}"
    # guardian_listen_web_interface: enp1s0
    # guardian_listen_web_ip: "{{ hostvars[inventory_hostname]['ansible_' ~ guardian_listen_web_interface]['ipv4']['address'] }}"

    guardian_approle_copy_remote_src: '{{ cube_vault_configs_dir }}' # References value defined in guardian_vault_config.yml for clarity
    guardian_access_token: '{{ guardian_access_token_vault }}' # References value defined in guardian_vault.yml for clarity
    ```

13. Create an Ansible playbook to deploy the required Vault Configuration, create Guardian SSL certificates, and install the Guardian software.

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

14. Run the playbook to configure the Guardian Node

```bash
ansible-playbook -i ./inventory/hosts-example.ini playbooks/guardian_vault_config.yml --diff -v
```
