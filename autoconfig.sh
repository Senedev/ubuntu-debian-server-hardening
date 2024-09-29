#!/bin/bash

# AUTOR:            Guilherme Henrique de Sene Oliveira
# CONTATO:          <guihenriquesene@gmail.com>
# DATA CRIAÇÃO:     27 Setembro 2024
# DATA ATUALIZAÇÃO: 29 Setembro 2024

# ======================

# [Controles]
ATUALIZAR=1                        # Atualizar o sistema?               1=SIM 0=NÃO
AUTO_ATUALIZAR_PCT=1               # Auto atualizar pacotes a cada 6h?  1=SIM 0=NÃO
IP_ESTATICO=1                      # Definir IP fixo no servidor?       1=SIM 0=NÃO
SSH=1                              # Configurar SSH para segurança?     1=SIM 0=NÃO
POLITICA_SENHA=1                   # Alterar políticas de senha?        1=SIM 0=NÃO
PERMISSOES=1                       # Ajustar permissões sensíveis?      1=SIM 0=NÃO
SELINUX=1                          # Ativar SELinux?                    1=SIM 0=NÃO
CRIPTOGRAFIA=1                     # Ativar criptografia de disco?      1=SIM 0=NÃO
BLOQUEAR_BOOT=1                    # Bloquear diretório de boot?        1=SIM 0=NÃO
USB=1                              # Bloquear dispositivos USB?         1=SIM 0=NÃO
BIOS=1                             # Ativar proteção da BIOS?           1=SIM 0=NÃO
SEG_ADICIONAL=1                    # Reforço adicional de segurança?    1=SIM 0=NÃO
REMOVER_SERVICOS=1                 # Remover serviços desnecessários?   1=SIM 0=NÃO
VERIFICAR_SEGURANCA=1              # Verificar segurança de arquivos?   1=SIM 0=NÃO
LIMITAR_ACESSO=1                   # Limitar ROOT ao sudo?              1=SIM 0=NÃO
XWINDOW=1                          # Desabilitar XWINDOW?               1=SIM 0=NÃO
MINIMIZAR_PCT=1                    # Instalar só pacotes essenciais?    1=SIM 0=NÃO
SENHAS_VAZIAS=1                    # Verificar senhas vazias?           1=SIM 0=NÃO
MONITORAR_ATV=1                    # Monitorar atividades de usuários?  1=SIM 0=NÃO
FAIL2BAN=1                         # Instalar/configurar fail2ban?      1=SIM 0=NÃO
ROOTKIT=1                          # Proteger/verificar rootkits?       1=SIM 0=NÃO
MONITORAR_LOGS=1                   # Monitorar logs do sistema?         1=SIM 0=NÃO
REINICIAR=1                        # Reiniciar após as operações?       1=SIM 0=NÃO

# [Variáveis]
IP="192.168.1.100/24"              # Endereço IP do servidor
GATEWAY="192.168.1.1"              # Gateway da rede
DNS1="8.8.8.8"                     # DNS primário
DNS2="9.9.9.9"                     # DNS secundário
PLACA_REDE=$(ip -o -4 route show to default | awk '{print $5}')  # Detecta placa de rede

# ======================

# Passo 0: Detecta a distribuição instalada
if grep -qi "Ubuntu" /etc/os-release; then
	ELEVAR="sudo"
elif grep -qi "Debian" /etc/os-release; then
	ELEVAR=""
else
	echo -e "\e[91mA sua distribuição não é Ubuntu e nem Debian.\e[0m"
fi

# Passo 1: Atualizar o sistema operacional e seus pacotes
if [[ "$ATUALIZAR" -eq 1 ]]; then
    echo -e "\e[33mPasso 1: Atualizando o sistema operacional e seus pacotes\e[0m"
    $ELEVAR apt update && $ELEVAR apt upgrade -y
    $ELEVAR apt full-upgrade -y
    if command -v snap > /dev/null 2>&1; then
        $ELEVAR snap refresh
    fi
    echo -e "\e[92mO sistema operacional e seus pacotes foram atualizados com sucesso!\e[0m"
    echo ""
fi

# Passo 2: Definir IP Fixo no servidor
if [[ "$IP_ESTATICO" -eq 1 ]]; then
    echo -e "\e[33mPasso 2: Definindo IP fixo do servidor local\e[0m"
    echo "Realizando o backup por segurança do arquivo de configuração de rede.."
    echo "Verificando se o sistema é Ubuntu ou Debian.."
    echo "Verificando se o arquivo de configuração existe.."    
    # Verifica se é Ubuntu
    if grep -qi "ubuntu" /etc/os-release; then
        if [[ -f /etc/netplan/50-cloud-init.yaml ]]; then
            $ELEVAR cp /etc/netplan/50-cloud-init.yaml /etc/netplan/50-cloud-init.yaml.bkp
            echo "Backup do arquivo de configuração do Netplan criado com sucesso."
            echo "Modificando as configurações de rede.."
			echo "network:" > /etc/netplan/50-cloud-init.yaml
			echo "  version: 2" >> /etc/netplan/50-cloud-init.yaml
			echo "  ethernets:" >> /etc/netplan/50-cloud-init.yaml
			echo "    $PLACA_REDE:" >> /etc/netplan/50-cloud-init.yaml
			echo "      dhcp4: no" >> /etc/netplan/50-cloud-init.yaml
			echo "      addresses:" >> /etc/netplan/50-cloud-init.yaml
			echo "        - $IP" >> /etc/netplan/50-cloud-init.yaml
			echo "      routes:" >> /etc/netplan/50-cloud-init.yaml
			echo "        - to: 0.0.0.0/0" >> /etc/netplan/50-cloud-init.yaml
			echo "          via: $GATEWAY" >> /etc/netplan/50-cloud-init.yaml
			echo "      nameservers:" >> /etc/netplan/50-cloud-init.yaml
			echo "        addresses:" >> /etc/netplan/50-cloud-init.yaml
			echo "          - $DNS1" >> /etc/netplan/50-cloud-init.yaml
			echo "          - $DNS2" >> /etc/netplan/50-cloud-init.yaml
			$ELEVAR netplan apply
			echo -e "\e[92mConfiguração de rede aplicada com sucesso!\e[0m"
			echo ""
        fi
    
    # Verifica se é Debian
    elif grep -qi "debian" /etc/os-release; then
        if [[ -f /etc/network/interfaces ]]; then
            $ELEVAR cp /etc/network/interfaces /etc/network/interfaces.bkp
            echo "Backup do arquivo de configuração de rede criado com sucesso."
            echo "Modificando as configurações de rede.."
            $ELEVAR sed -i "/^iface $PLACA_REDE inet /d" /etc/network/interfaces
			$ELEVAR sed -i "/^auto $PLACA_REDE/d" /etc/network/interfaces
			echo "auto $PLACA_REDE" | $ELEVAR tee -a /etc/network/interfaces
			echo "iface $PLACA_REDE inet static" | $ELEVAR tee -a /etc/network/interfaces
			echo "    address $IP" | $ELEVAR tee -a /etc/network/interfaces
			echo "    netmask 255.255.255.0" | $ELEVAR tee -a /etc/network/interfaces
			echo "    gateway $GATEWAY" | $ELEVAR tee -a /etc/network/interfaces
			echo "    dns-nameservers $DNS1 $DNS2" | $ELEVAR tee -a /etc/network/interfaces
			$ELEVAR systemctl restart networking
			echo -e "\e[92mConfiguração de rede aplicada com sucesso!\e[0m"
			echo ""
        fi
    fi
fi

# Passo 3: Segurança de acesso e SSH
if [[ "$SSH" -eq 1 ]]; then
	echo -e "\e[33mEtapa 3: Segurança de acesso e SSH\e[0m"
	echo "Segurança de acesso e SSH"
	echo "Verificando se o arquivo de configuração do SSH existe.."
	if [[ -f /etc/ssh/sshd_config ]]; then
		echo "Realizando o backup por segurança do arquivo de configuração de rede.."
		$ELEVAR cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bkp
		echo "Backup realizado!"
	fi
	echo "Alterando a porta de acesso.."
	sed -i "s/^#Port 22/Port 9989/g" /etc/ssh/sshd_config
	echo "Proibindo acesso via usuário root.."
	sed -i "s/^#PermitRootLogin prohibit-password/PermitRootLogin no/g" /etc/ssh/sshd_config
	echo "Diminuindo o limite de tentativas de conexão.."
	sed -i "s/#MaxAuthTries 6/MaxAuthTries 3/g" /etc/ssh/sshd_config
	echo "Diminuindo o número de usuários logados simultâneamente.."
	sed -i "s/#MaxSessions 10/MaxSessions 2/g" /etc/ssh/sshd_config
	echo "Permitindo acesso via chave pública.."
	sed -i "s/#PubkeyAuthentication yes/PubkeyAuthentication yes/g" /etc/ssh/sshd_config
	echo "Habilitando o arquivo responsável pela chave pública do SSH.."
	sed -i "s/^#AuthorizedKeysFile[[:space:]]\+.ssh/authorized_keys .ssh/authorized_keys2/AuthorizedKeysFile .ssh/authorized_keys/g" /etc/ssh/sshd_config
	echo "Proibindo acesso via senha (password).."
	sed -i "s/^#PasswordAuthentication yes/PasswordAuthentication no/g" /etc/ssh/sshd_config
	echo "Proibindo acesso sem senha.."
	sed -i "s/#PermitEmptyPasswords no/PermitEmptyPasswords no/g" /etc/ssh/sshd_config
	echo "Desativando o X11 Forwarding.."
	sed -i "s/^#X11Forwarding no/X11Forwarding no/g" /etc/ssh/sshd_config
	echo "Reiniciando o serviço SSH para aplicar as mudanças.."
	if grep -qi "ubuntu" /etc/os-release; then
		$ELEVAR systemctl restart ssh.service
	elif grep -qi "debian" /etc/os-release; then
	 	$ELEVAR systemctl restart ssh
	fi
	echo -e "\e[92mConfiguração de acesso e SSH ajustados com sucesso!\e[0m"
	echo ""
fi

# Passo 4: Habilitando atualização automática de pacotes
if [[ "$AUTO_ATUALIZAR_PCT" -eq 1 ]]; then
	echo -e "\e[33mEtapa 4: Habilitando atualização automática de pacotes\e[0m"
	echo "Habilitando atualização automática de pacotes"
	$ELEVAR apt update && $ELEVAR apt install unattended-upgrades -y
	echo "Realizando ajustes nos arquivos necessários.."
	sed -i 's/^APT::Periodic::Update-Package-Lists "720";/APT::Periodic::Update-Package-Lists "360";/g' /etc/apt/apt.conf.d/20auto-upgrades
	sed -i 's/^APT::Periodic::Unattended-Upgrade "720";/APT::Periodic::Unattended-Upgrade "360";/g' /etc/apt/apt.conf.d/20auto-upgrades
	sed -i 's/^APT::Periodic::Download-Upgradeable-Packages "720";/APT::Periodic::Download-Upgradeable-Packages "360";/g' /etc/apt/apt.conf.d/20auto-upgrades
	sed -i 's/^APT::Periodic::AutocleanInterval "720";/APT::Periodic::AutocleanInterval "360";/g' /etc/apt/apt.conf.d/20auto-upgrades
	sed -i 's/^\/\/[[:space:]]*"\${distro_id}:\${distro_codename}-updates";/"\${distro_id}:\${distro_codename}-updates";/g' /etc/apt/apt.conf.d/50unattended-upgrades
	sed -i 's/^//Unattended-Upgrade::AutoFixInterruptedDpkg "true";/Unattended-Upgrade::AutoFixInterruptedDpkg "true";/g' /etc/apt/apt.conf.d/50unattended-upgrades
	sed -i 's/^//Unattended-Upgrade::Automatic-Reboot "false";/Unattended-Upgrade::Automatic-Reboot "true";/g' /etc/apt/apt.conf.d/50unattended-upgrades
	echo "0 */6 * * * /usr/bin/unattended-upgrade" | $ELEVAR tee -a /var/spool/cron/crontabs/root
	echo -e "\e[92mO sistema foi configurado com sucesso para realizar atualizações automáticas a cada 6 horas!\e[0m"
	echo ""
fi

# Passo 5: Proteção da BIOS
if [[ "$BIOS" -eq 1 ]]; then
	echo -e "\e[33mPasso 2: Proteção do BIOS\e[0m"
    echo "Verificando se a proteção do BIOS está ativada..."
    if [ -f /sys/devices/system/cpu/microcode/reload ]; then
      echo "A proteção do BIOS está ativada"
    else
      echo "A proteção do BIOS não está ativada"
    fi
    echo ""
fi

# Passo 6: Criptografia do disco rígido
if [[ "$CRIPTOGRAFIA" -eq 1 ]]; then
	echo -e "\e[33mPasso 6: Criptografia do disco rígido\e[0m"
    echo "Verificando se a criptografia do disco rígido está ativada..."
    if [ -d /etc/luks ]; then
      echo "A criptografia do disco rígido está ativada"
    else
      echo "A criptografia do disco rígido não está ativada"
    fi
    echo ""
fi

# Passo 7: Bloquear o diretório de boot
if [[ "$BLOQUEAR_BOOT" -eq 1 ]]; then
	echo -e "\e[33mPasso 7: Bloquear o diretório de boot\e[0m"
    echo "Bloqueando o diretório de boot..."
    $ELEVAR chmod 700 /boot
    echo ""
fi

# Passo 8: Desativar o uso da USB
if [[ "$USB" -eq 1 ]]; then
	echo -e "\e[33mPasso 8: Desativar o uso de USB\e[0m"
    echo "Desativando o uso de USB..."
    echo 'blacklist usb-storage' | $ELEVAR tee /etc/modprobe.d/blacklist-usbstorage.conf
    echo ""
fi

# Passo 9: Ativa o SElinux
if [[ "$SELINUX" -eq 1 ]]; then
	echo -e "\e[33mPasso 9: Ativar o SELinux\e[0m"
    echo "Verificando se o SELinux está instalado..."
    if [ -f /etc/selinux/config ]; then
      echo "O SELinux já está instalado"
    else
      echo "O SELinux não está instalado, instalando agora..."
      $ELEVAR apt-get install policycoreutils selinux-utils selinux-basics -y
    fi
    echo "Ativando o SELinux..."
    $ELEVAR selinux-activate
    echo ""
fi

# Passo 10: Gerenciar políticas de senha
if [[ "$POLITICA_SENHA" -eq 1 ]]; then
	echo -e "\e[33mPasso 10: Gerenciar políticas de senha\e[0m"
    echo "Modificando as políticas de senha..."
    $ELEVAR sed -i 's/PASS_MAX_DAYS\t99999/PASS_MAX_DAYS\t90/g' /etc/login.defs
    $ELEVAR sed -i 's/PASS_MIN_DAYS\t0/PASS_MIN_DAYS\t7/g' /etc/login.defs
    $ELEVAR sed -i 's/PASS_WARN_AGE\t7/PASS_WARN_AGE\t14/g' /etc/login.defs
    echo ""
fi

# Passo 11: Permissões e verificações
if [[ "$PERMISSOES" -eq 1 ]]; then
	echo -e "\e[33mPasso 11: Permissões e verificações\e[0m"
    echo "Configurando as permissões corretas em arquivos sensíveis..."
    $ELEVAR chmod 700 /etc/shadow /etc/gshadow /etc/passwd /etc/group
    $ELEVAR chmod 600 /boot/grub/grub.cfg
    $ELEVAR chmod 644 /etc/fstab /etc/hosts /etc/hostname /etc/timezone /etc/bash.bashrc
    echo "Verificando a integridade dos arquivos do sistema..."
    $ELEVAR debsums -c
    echo ""
fi

# Passo 12: Reforço adicional do processo de distribuição
if [[ "$SEG_ADICIONAL" -eq 1 ]]; then
	echo -e "\e[33mPasso 12: Reforço adicional do processo de distribuição\e[0m"
    echo "Desabilitando despejos de núcleo..."
    $ELEVAR echo '* hard core 0' | $ELEVAR tee /etc/security/limits.d/core.conf
    echo "Restringindo o acesso aos logs do kernel..."
    $ELEVAR chmod 640 /var/log/kern.log
    echo "Configurando as permissões corretas nos scripts de inicialização..."
    $ELEVAR chmod 700 /etc/init.d/*
    echo ""
fi

# Passo 13: Remover serviços desnecessários
if [[ "$REMOVER_SERVICOS" -eq 1 ]]; then
	echo -e "\e[33mPasso 13: Remover serviços desnecessários\e[0m"
    echo "Removendo serviços desnecessários..."
    $ELEVAR apt-get purge rpcbind rpcbind-* -y
    $ELEVAR apt-get purge nis -y
    echo ""
fi

# Passo 14: Verificar a segurança dos arquivos-chave
if [[ "$VERIFICAR_SEGURANCA" -eq 1 ]]; then
	echo -e "\e[33mPasso 14: Verificar a segurança dos arquivos-chave\e[0m"
    echo "Verificando a segurança dos arquivos-chave..."
    $ELEVAR find /etc/ssh -type f -name 'ssh_host_*_key' -exec chmod 600 {} \;
    echo ""
fi

# Passo 15: Limitar o acesso root usando o SUDO
if [[ "$LIMITAR_ACESSO" -eq 1 ]]; then
	echo -e "\e[33mPasso 15: Limitar o acesso root usando o SUDO\e[0m"
    echo "Limitando o acesso root usando o sudo..."
    $ELEVAR apt-get install sudo -y
    $ELEVAR groupadd admin
    $ELEVAR usermod -a -G admin "$(whoami)"
    $ELEVAR sed -i 's/%sudo\tALL=(ALL:ALL) ALL/%admin\tALL=(ALL:ALL) ALL/g' /etc/sudoers
    echo ""
fi

# Passo 16: Desabilitar o Xwindow
if [[ "$XWINDOW" -eq 1 ]]; then
	echo -e "\e[33mPasso 16: Desabilitar o Xwindow\e[0m"
    echo "Desabilitando o Xwindow..."
    $ELEVAR systemctl set-default multi-user.target
    echo ""
fi

# Passo 17: Minimizar a instalação de pacotes
if [[ "$MINIMIZAR_PCT" -eq 1 ]]; then
	echo -e "\e[33mPasso 17: Minimizar a instalação de pacotes\e[0m"
    echo "Instalando apenas pacotes essenciais..."
    $ELEVAR apt-get install --no-install-recommends -y systemd-sysv apt-utils
    $ELEVAR apt-get --purge autoremove -y
    echo ""
fi

# Passo 18: Verificar contas com senhas vazias
if [[ "$SENHAS_VAZIAS" -eq 1 ]]; then
	echo -e "\e[33mPasso 18: Verificar contas com senhas vazias\e[0m"
    echo "Verificando contas com senhas vazias..."
    $ELEVAR awk -F: '($2 == "" ) {print}' /etc/shadow
    echo ""
fi

# Passo 19:  Monitorar atividades do usuário
if [[ "$MONITORAR_ATV" -eq 1 ]]; then
	echo -e "\e[33mPasso 19: Monitorar atividades do usuário\e[0m"
    echo "Instalando auditd para monitoramento de atividades do usuário..."
    $ELEVAR apt-get install auditd -y
    echo "Configurando o auditd..."
    $ELEVAR echo "-w /var/log/auth.log -p wa -k authentication" | $ELEVAR tee -a /etc/audit/rules.d/audit.rules
    $ELEVAR echo "-w /etc/passwd -p wa -k password-file" | $ELEVAR tee -a /etc/audit/rules.d/audit.rules
    $ELEVAR echo "-w /etc/group -p wa -k group-file" | $ELEVAR tee -a /etc/audit/rules.d/audit.rules
    $ELEVAR systemctl restart auditd
    echo ""
fi

# Passo 20: Instalar e configurar fail2ban
if [[ "$FAIL2BAN" -eq 1 ]]; then
	echo -e "\e[33mPasso 20: Instalar e configurar fail2ban\e[0m"
    echo "Instalando fail2ban..."
    $ELEVAR apt-get install fail2ban -y
    echo "Configurando fail2ban..."
    $ELEVAR cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
    $ELEVAR sed -i 's/bantime  = 10m/bantime  = 1h/g' /etc/fail2ban/jail.local
    $ELEVAR sed -i 's/maxretry = 5/maxretry = 3/g' /etc/fail2ban/jail.local
    $ELEVAR systemctl enable fail2ban
    $ELEVAR systemctl start fail2ban
    echo ""
fi

# Passo 21: Detecção de rootkits
if [[ "$ROOTKIT" -eq 1 ]]; then
	echo -e "\e[33mPasso 21: Instalando e executando a detecção de rootkits...\e[0m"
    $ELEVAR apt-get install rkhunter
    $ELEVAR rkhunter --update
    $ELEVAR rkhunter --propupd
    $ELEVAR rkhunter --check
    echo
fi

# Passo 22: Monitorar logs do sistema
if [[ "$MONITORAR_LOGS" -eq 1 ]];
	echo -e "\e[33mPasso 22: Monitorar logs do sistema\e[0m"
    echo "Instalando logwatch para monitoramento de logs do sistema..."
    $ELEVAR apt-get install logwatch -y
    echo ""
fi

# Passo 23: Reiniciar o sistema operacional
if [[ "$REINICIAR" -eq 1 ]]; then
	echo -e "\e[33mPasso 23: Reiniciar o sistema operacional\e[0m"
	if grep -qi "Ubuntu" /etc/os-release; then
		$ELEVAR shutdown -r now
	elif grep -qi "Debian" /etc/os-release; then
		$ELEVAR systemctl poweroff
fi
