#!/bin/bash

GREEN='\e[32m'
YELLOW='\e[33m'
RED='\e[31m'
BLUE='\e[94m'
NC='\e[0m' # No Color

###############################################################
##### Função para verificar a instalação do apache2-utils #####
###############################################################

check_apache2_utils() {
    echo -e "${BLUE}Verificando a instalação do apache2-utils...${NC}"
    if ! command -v htpasswd &> /dev/null; then
        echo -e "${YELLOW}Instalando apache2-utils...${NC}"

        (sudo apt-get update -y && sudo apt-get install apache2-utils -y) > /dev/null 2>&1 & spinner $!
        wait $!
        if [ $? -ne 0 ]; then
        echo -e "${RED}❌ Erro ao instalar apache2-utils. Verifique sua conexão ou permissões.${NC}"
        return 1 # Adicionado para indicar falha
        fi        
        echo -e "${GREEN}✅ apache2-utils instalado com sucesso!${NC}"
    else
        echo -e "${GREEN}✅ apache2-utils já está instalado.${NC}"
    fi
    return 0
}

###########################################
##### Função para verificar o OpenSSL #####
###########################################
check_openssl() {
    echo -e "${BLUE}Verificando a instalação do openssl...${NC}"
    if ! command -v openssl &> /dev/null; then
        echo -e "${YELLOW}Instalando openssl...${NC}"
        (sudo apt-get update -y && sudo apt-get install openssl -y) > /dev/null 2>&1 & spinner $!
        wait $!
        if [ $? -ne 0 ]; then
            echo -e "${RED}❌ Erro ao instalar openssl. Verifique sua conexão ou permissões.${NC}"
            return 1
        fi
        echo -e "${GREEN}✅ openssl instalado com sucesso!${NC}"
    else
        echo -e "${GREEN}✅ openssl já está instalado.${NC}"
    fi
    return 0
}

#################################################
##### Função para configurar o Firewall UFW #####
#################################################
configure_firewall() {
    echo -e "${BLUE}Configurando o firewall (UFW)...${NC}"
    if ! command -v ufw &> /dev/null; then
        echo -e "${YELLOW}Instalando UFW...${NC}"
        (sudo apt-get update -y && sudo apt-get install ufw -y) > /dev/null 2>&1 & spinner $!
        wait $!
        if [ $? -ne 0 ]; then
            echo -e "${RED}❌ Erro ao instalar UFW.${NC}"
            return 1
        fi
    fi
    
echo -e "${YELLOW}Liberando portas essenciais...${NC}"
    (
        sudo ufw allow 22/tcp      # IMPORTANTE: Garante que a conexão SSH não seja perdida
        sudo ufw allow 80/tcp      # Porta HTTP para redirecionamento do Traefik
        sudo ufw allow 443/tcp     # Porta HTTPS para tráfego seguro do Traefik
        # Portas necessárias para o funcionamento do Docker Swarm
        sudo ufw allow 2377/tcp    # Comunicação de gerenciamento do cluster
        sudo ufw allow 7946/tcp    # Comunicação entre nós
        sudo ufw allow 7946/udp    # Comunicação entre nós
        sudo ufw allow 4789/udp    # Rede overlay
    ) > /dev/null 2>&1

    echo -e "${YELLOW}Ativando o UFW...${NC}"
    (echo "y" | sudo ufw enable) > /dev/null 2>&1

    echo -e "${GREEN}✅ Firewall configurado e ativo.${NC}"
    # Apenas para mostrar um output mais limpo e focado
    (sudo ufw status | head -n 1 && sudo ufw status | grep -E '80|22|443|2377|7946|4789') || sudo ufw status
    return 0
}

###############################################################
##### Função para gerar certificados TLS para o Portainer #####
###############################################################
generate_portainer_certs() {
    echo -e "${BLUE}Gerando certificados TLS para comunicação segura Portainer <-> Agent...${NC}"
    local CERT_DIR="/docker/portainer/certs"
    sudo mkdir -p "$CERT_DIR"

    (
    # Gerar a chave e o certificado da Autoridade Certificadora (CA)
    sudo openssl genrsa -out "${CERT_DIR}/ca.key" 4096
    sudo openssl req -x509 -new -nodes -key "${CERT_DIR}/ca.key" -sha256 -days 3650 -subj "/C=BR/ST=SP/L=SaoPaulo/O=Portainer/CN=portainer.ca" -out "${CERT_DIR}/ca.pem"

    # Gerar a chave e a solicitação de assinatura (CSR) para o Agent
    sudo openssl genrsa -out "${CERT_DIR}/agent.key" 4096
    sudo openssl req -new -key "${CERT_DIR}/agent.key" -subj "/C=BR/ST=SP/L=SaoPaulo/O=Portainer/CN=tasks.agent" -out "${CERT_DIR}/agent.csr"

    # Assinar o certificado do Agent com a nossa CA
    sudo openssl x509 -req -in "${CERT_DIR}/agent.csr" -CA "${CERT_DIR}/ca.pem" -CAkey "${CERT_DIR}/ca.key" -CAcreateserial -out "${CERT_DIR}/agent.pem" -days 3650 -sha256

    # Gerar a chave e a solicitação de assinatura (CSR) para o Cliente (Portainer)
    sudo openssl genrsa -out "${CERT_DIR}/client.key" 4096
    sudo openssl req -new -key "${CERT_DIR}/client.key" -subj "/C=BR/ST=SP/L=SaoPaulo/O=Portainer/CN=portainer.client" -out "${CERT_DIR}/client.csr"

    # Assinar o certificado do Cliente com a nossa CA
    sudo openssl x509 -req -in "${CERT_DIR}/client.csr" -CA "${CERT_DIR}/ca.pem" -CAkey "${CERT_DIR}/ca.key" -CAcreateserial -out "${CERT_DIR}/client.pem" -days 3650 -sha256

    # Remover os CSRs que não são mais necessários
    sudo rm "${CERT_DIR}/agent.csr"
    sudo rm "${CERT_DIR}/client.csr"
    ) > /dev/null 2>&1 & spinner $!
    wait $!

    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✅ Certificados TLS gerados com sucesso em ${CERT_DIR}${NC}"
        return 0
    else
        echo -e "${RED}❌ Erro ao gerar os certificados TLS.${NC}"
        return 1
    fi
}

#######################################################
##### Função para mostrar spinner de carregamento #####
#######################################################
spinner() {
    local pid=$1
    local delay=0.1
    local spinstr='|/-\'
    while kill -0 $pid 2>/dev/null; do   
        local temp=${spinstr#?}
        printf " [%c]  " "$spinstr"
        local spinstr=$temp${spinstr%"$temp"}
        sleep $delay
        printf "\b\b\b\b\b\b"
    done
    printf "    \b\b\b\b"
}

########################################################
###### Função para verificar requisitos do sistema #####
########################################################

check_system_requirements() {
    echo -e "${BLUE}Verificando requisitos do sistema...${NC}"

    # Verificar se é Ubuntu/Debian
    if ! command -v apt-get &> /dev/null; then
        echo -e "${RED}❌ Erro: Este script é para sistemas baseados em Debian/Ubuntu${NC}"
        return 1
    fi

    # Verificar espaço em disco (em GB, removendo a unidade 'G')
    local free_space=$(df -BG / | awk 'NR==2 {print $4}' | tr -d 'G')
    if [ "$free_space" -lt 15 ]; then
        echo -e "${RED}❌ Erro: Espaço em disco insuficiente. Mínimo requerido: 15GB. Livre: ${free_space}GB${NC}"
        return 1
    fi

    # Verificar memória RAM
    local total_mem=$(free -g | awk 'NR==2 {print $2}')
    if [ "$total_mem" -lt 2 ]; then
        echo -e "${RED}❌ Erro: Memória RAM insuficiente. Mínimo requerido: 2GB. Disponível: ${total_mem}GB${NC}"
        return 1
    fi

    # Verificar se tem privilégios de sudo
    if ! sudo -n true 2>/dev/null; then
        echo -e "${RED}❌ Erro: É necessário ter privilégios de sudo${NC}"
        return 1
    fi

    echo -e "${GREEN}✅ Requisitos do sistema atendidos${NC}"
    return 0
}

###############################################################
##### Função para verificar se o Docker já está instalado #####
###############################################################

check_docker_installed() {
    if command -v docker &> /dev/null; then
        echo -e "${GREEN}✅ Docker já está instalado.${NC}"
        return 0
    else
        echo -e "${YELLOW}🐳 Docker não encontrado. Será instalado.${NC}"
        return 1
    fi
}

#######################################################
##### Definição da função de instalação do Docker #####
#######################################################

install_docker_function() {

    local distro=$(lsb_release -si 2>/dev/null || echo "ubuntu")
    local distro_lower=$(echo "$distro" | tr '[:upper:]' '[:lower:]')
    
    # Atualizar repositórios
    sudo apt-get update -y && \
    # Instalar dependências
    sudo apt-get install ca-certificates curl gnupg lsb-release -y && \
    # Criar diretório para chaves
    sudo install -m 0755 -d /etc/apt/keyrings && \
    # Baixar chave GPG do Docker
    sudo curl -fsSL https://download.docker.com/linux/${distro_lower}/gpg -o /etc/apt/keyrings/docker.asc && \
    # Definir permissões da chave
    sudo chmod a+r /etc/apt/keyrings/docker.asc && \
    # Adicionar repositório Docker
    echo \
      "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/${distro_lower} \
      $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
      sudo tee /etc/apt/sources.list.d/docker.list > /dev/null && \
      # Atualizar novamente e instalar Docker
    sudo apt-get update -y && \
    sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin && \
    # Adicionar usuário atual ao grupo docker
    sudo usermod -aG docker $USER && \
    newgrp docker && \
    # Iniciar e habilitar Docker
    sudo systemctl start docker && \
    sudo systemctl enable docker
}

#########################
###### Logo animado #####
#########################

show_animated_logo() {
    clear
    echo -e "${BLUE}"
    echo -e "██      ▄██████▄  ▄██████▄  ███████▄  ██  ██  █▄    ██"
    echo -e "██      ██    ██  ██    ██  ██    ██  ██  ██  ███▄  ██"
    echo -e "██      ██    ██  ██    ██  ███████▀  ██  ██  ██▀██▄██"
    echo -e "██      ██    ██  ██    ██  ██        ██  ██  ██  ▀███"
    echo -e "██████  ▀██████▀  ▀██████▀  ██        ██  ██  ██    ▀█"
    echo -e "${NC}"   
}

##################################################
##### Função para mostrar um banner colorido #####
##################################################

function show_banner() {

    echo -e "${BLUE}"
    echo -e "█▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀█"    
    echo -e "█     Preencha as informações solicitadas abaixo     █"   
    echo -e "█▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄█"
    echo -e "${NC}"
}

############################################################################
##### Função para mostrar uma mensagem de etapa com barra de progresso #####
############################################################################

function show_step() {
    local current=$1
    local total=6
    local percent=$((current * 100 / total))
    local completed=$((percent / 2)) # 50 caracteres para a barra

    echo -ne "${GREEN}Passo ${YELLOW}$current/$total ${GREEN}["
    for ((i=0; i<50; i++)); do
        if [ $i -lt $completed ]; then
            echo -ne "●"
        else
            echo -ne " "
        fi
    done
    echo -e "] ${percent}%${NC}"
}

######################################
##### Função para validar e-mail #####
######################################

validate_email() {
    local email_regex="^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    if [[ $1 =~ $email_regex ]]; then
        return 0 # Válido
    else
        return 1 # Inválido
    fi
}

#################################################################################
##### Função para validar domínio (formato específico: pelo menos 3 partes) #####
#################################################################################

validate_domain() {    
    local domain_regex="^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$"
    if [[ "$1" =~ $domain_regex ]] && [[ ${#1} -le 253 ]]; then
        return 0 # Válido
    else
        return 1 # Inválido
    fi
}

#######################################
##### Função para validar usuário #####
#######################################

validate_user() {    
    local domain_regex="^[a-zA-Z0-9_]{4,}$"
    if [[ "$1" =~ $domain_regex ]]; then
        return 0 # Válido
    else
        return 1 # Inválido
    fi
}

#####################################################
##### Função para validar complexidade da senha #####
#####################################################

validate_password_complexity() {
    local password="$1"
    if (( ${#password} < 8 )); then
        echo -e "${RED}❌ Senha muito curta. Mínimo de 8 caracteres.${NC}"
        return 1
    fi
    if ! [[ "$password" =~ [[:digit:]] ]]; then
        echo -e "${RED}❌ Senha deve conter ao menos um número.${NC}"
        return 1
    fi
    if ! [[ "$password" =~ [[:upper:]] ]]; then
        echo -e "${RED}❌ Senha deve conter ao menos uma letra maiúscula.${NC}"
        return 1
    fi
    if ! [[ "$password" =~ [[:lower:]] ]]; then
        echo -e "${RED}❌ Senha deve conter ao menos uma letra minúscula.${NC}"
        return 1
    fi
    if ! [[ "$password" =~ [[:punct:]] ]]; then # Caracteres de pontuação
        echo -e "${RED}❌ Senha deve conter ao menos um caractere especial (ex: !@#$%^&*).${NC}"
        return 1
    fi
    return 0 # Válido
}

##################################
##### Mostrar banner inicial #####
##################################

clear
show_animated_logo
sleep 1
show_banner
echo ""

##########################################################
##### Solicitar informações do usuário com validação #####
##########################################################

show_step 1
while true; do
    read -p "📧 Endereço de e-mail (para certificados SSL): " email
    if validate_email "$email"; then
        echo -e "${GREEN}✅ E-mail válido.${NC}"
        break
    else
        echo -e "${RED}❌ E-mail inválido. Por favor, insira um endereço de e-mail válido (ex: seu.email@dominio.com).${NC}"
    fi
done

clear
show_animated_logo
show_banner
echo ""

show_step 2
while true; do
    read -p "🌐 Dominio do Traefik (ex: traefik.seudominio.com): " traefik_domain
    if validate_domain "$traefik_domain"; then
        echo -e "${GREEN}✅ Domínio válido.${NC}"
        break
    else
        echo -e "${RED}❌ Domínio inválido. Por favor, insira um domínio válido.${NC}"
    fi
done

clear
show_animated_logo
show_banner
echo ""

show_step 3
while true; do
    read -p "👮 Usuário do Traefik (ex: admin): " traefik_user
    if validate_user "$traefik_user"; then
        echo -e "${GREEN}✅ Usuário válido.${NC}"
        break
    else
        echo -e "${RED}❌ Usuário inválido. Use apenas letras, números e underscore. Mínimo de 4 caracteres.${NC}"
    fi
done

clear
show_animated_logo
show_banner
echo ""

show_step 4
while true; do
    read -s -p "🔑 Senha do Traefik (mínimo 8 caracteres, com maiúscula, minúscula, número e especial): " traefik_senha
    echo "" # Quebra de linha após a entrada da senha oculta
    read -s -p "🔁 Confirme a Senha do Traefik: " traefik_senha_confirm
    echo "" # Quebra de linha após a entrada da senha de confirmação oculta

    if [[ "$traefik_senha" == "$traefik_senha_confirm" ]]; then
        if validate_password_complexity "$traefik_senha"; then
            echo -e "${GREEN}✅ Senha aceita.${NC}"
            break
        fi
    else
        echo -e "${RED}❌ As senhas não coincidem. Por favor, tente novamente.${NC}"
    fi
done

clear
show_animated_logo
show_banner
echo ""

show_step 5
while true; do
    read -p "🌐 Dominio do Portainer (ex: portainer.seudominio.com): " portainer_domain
    if validate_domain "$portainer_domain"; then
        echo -e "${GREEN}✅ Domínio válido.${NC}"
        break
    else
        echo -e "${RED}❌ Domínio inválido. Por favor, insira um domínio válido.${NC}"
    fi
done

clear
show_animated_logo
show_banner
echo ""

show_step 6
while true; do
    read -p "🌐  Dominio do Edge (ex: edge.seudominio.com): " edge_domain
    if validate_domain "$edge_domain"; then
        echo -e "${GREEN}✅ Domínio válido.${NC}"
        break
    else
        echo -e "${RED}❌ Domínio inválido. Por favor, insira um domínio válido.${NC}"
    fi
done

################################
##### Verificação de dados #####
################################

clear
echo -e "${BLUE}📋 Resumo das Informações${NC}"
echo -e "${GREEN}================================${NC}"
echo -e "📧 Seu E-mail: ${YELLOW}$email${NC}"
echo -e "🌐 Dominio do Traefik: ${YELLOW}$traefik_domain${NC}"
echo -e "👮 Usuário do Traefik: ${YELLOW}$traefik_user${NC}"
echo -e "🔑 Senha do Traefik: ${YELLOW}********${NC}" # Apenas para visualização
echo -e "🌐 Dominio do Portainer: ${YELLOW}$portainer_domain${NC}"
echo -e "🌐 Dominio do Edge: ${YELLOW}$edge_domain${NC}"
echo -e "${GREEN}================================${NC}"
echo ""

read -p "As informações estão certas? (y/n): " confirma1
if [[ "$confirma1" =~ ^[Yy]$ ]]; then
    clear

    ###########################################
    ##### Verificar requisitos do sistema #####
    ###########################################
    
    check_system_requirements || { echo -e "${RED}❌ Instalação cancelada devido a requisitos do sistema não atendidos.${NC}"; exit 1; }

    echo -e "${BLUE}🚀 Iniciando instalação ...${NC}"

    ###################################
    ##### INSTALANDO DEPENDENCIAS ##### 
    ###################################
   
    echo -e "${YELLOW}📦 Atualizando sistema e instalando dependências...${NC}"
    
    (sudo apt-get update -y && sudo apt-get upgrade -y) > /dev/null 2>&1 & spinner $!
    wait $!
    
    if [ $? -ne 0 ]; then
        echo -e "${RED}❌ Erro ao atualizar o sistema e instalar dependências. Verifique sua conexão ou permissões.${NC}"
        exit 1
    fi
    check_apache2_utils || { echo -e "${RED}❌ Não foi possível instalar o apache2-utils. Saindo.${NC}"; exit 1; }
    check_openssl || { echo -e "${RED}❌ Não foi possível instalar o openssl. Saindo.${NC}"; exit 1; }
   
    # Configuração do Firewall
    configure_firewall || { echo -e "${RED}❌ Não foi possível configurar o firewall. Saindo.${NC}"; exit 1; }

    encrypted_password=$(htpasswd -nb -B -C 10 "$traefik_user" "$traefik_senha")
    
    echo -e "${GREEN}✅ Sistema atualizado e dependências básicas instaladas.${NC}"

    ###################################################################
    ##### Verificar se o Docker já está instalado, senão instalar #####
    ###################################################################   
    
    if ! check_docker_installed; then
        echo -e "${YELLOW}🐳 Instalando Docker...${NC}"

        install_docker_function > /dev/null 2>&1 & spinner $!
        wait $!
               
        if [ $? -ne 0 ]; then
            echo -e "${RED}❌ Erro ao instalar o Docker. Por favor, verifique a saída do comando.${NC}"
            exit 1
        fi
        echo -e "${GREEN}✅ Docker instalado com sucesso.${NC}"
    fi

    echo -e "${YELLOW}📁 Criando diretórios e configurando...${NC}"
    (sudo mkdir -p /docker/traefik && sudo mkdir -p /docker/portainer/data) > /dev/null 2>&1 & spinner $!
    wait $!
    if [ $? -ne 0 ]; then
        echo -e "${RED}❌ Erro ao criar diretórios. Verifique suas permissões.${NC}"
        exit 1
    fi
    echo -e "${GREEN}✅ Diretórios criados com sucesso.${NC}"    

    # Gerar os certificados antes de criar o docker-swarm.yml
    generate_portainer_certs || { echo -e "${RED}❌ Falha na geração de certificados. Saindo.${NC}"; exit 1; }
   
    ######################################
    ##### CRIANDO DOCKER-SWARM.YML #####
    ######################################

    # Entra no diretório /docker para criar os arquivos
    cd /docker || { echo -e "${RED}❌ Não foi possível mudar para o diretório /docker.${NC}"; exit 1; }
    
   echo -e "${YELLOW}📝 Criando docker-swarm.yml...${NC}"
    cat <<EOL | sudo tee docker-swarm.yml > /dev/null
services:  
  traefik:
    image: traefik:v3.4.1
    container_name: traefik 
    networks:
      - web
    ports:
      - target: 80
        published: 80
        protocol: tcp
        mode: ingress
        #mode: host
      - target: 443
        published: 443
        protocol: tcp
        mode: ingress
        #mode: host
    volumes:
      - /etc/localtime:/etc/localtime
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - /docker/traefik/traefik.toml:/traefik.toml
      - /docker/traefik/traefik_dynamic.toml:/traefik_dynamic.toml
      - /docker/traefik/acme.json:/acme.json    
    deploy:
      mode: replicated
      replicas: 1
      placement:
        constraints: [node.role == manager]
      restart_policy:
        condition: on-failure
        delay: 10s           # Aguarda 10s antes de tentar
        max_attempts: 3      # Máximo 3 tentativas
        window: 180s         # Em uma janela de 3 minutos    
    logging:
      options:
        max-size: "10m"
        max-file: "3"    
  agent:
    image: portainer/agent:lts
    container_name: portainer-agent    
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
      - /var/lib/docker/volumes:/var/lib/docker/volumes      
      - /docker/portainer/certs/ca.pem:/certs/ca.pem:ro
      - /docker/portainer/certs/agent.pem:/certs/cert.pem:ro
      - /docker/portainer/certs/agent.key:/certs/key.pem:ro
    labels:
      - "traefik.enable=false" 
    networks:
      - agent_network
    deploy:
      mode: global
      placement:
        constraints: [node.platform.os == linux]
    logging:
      options:
        max-size: "10m"
        max-file: "3"    

  portainer:
    image: portainer/portainer-ce:lts
    container_name: portainer-ce
    command:      
      - -H
      - tcp://tasks.agent:9001
      - --tlsverify
      - --tlscacert=/certs/ca.pem
    volumes:
      - portainer_data:/data      
      - /docker/portainer/certs/ca.pem:/certs/ca.pem:ro
    networks:
      - agent_network
      - web
    deploy:
      mode: replicated
      replicas: 1
      placement:
        constraints: [node.role == manager]
      restart_policy:
        condition: on-failure
        delay: 15s           # Aguarda 15s antes de tentar
        max_attempts: 3      # Máximo 3 tentativas
        window: 180s         # Em uma janela de 3 minutos
    labels:
      - "traefik.enable=true"
      - "traefik.docker.network=web"
    # Roteador e Serviço para a interface principal do Portainer (porta 9000)
      - "traefik.http.routers.portainer.rule=Host(\`$portainer_domain\`) || Host(\`www.$portainer_domain\`)"
      - "traefik.http.routers.portainer.entrypoints=websecure"
      - "traefik.http.routers.portainer.tls=true"
      - "traefik.http.routers.portainer.tls.certresolver=lets-encrypt"
      - "traefik.http.services.portainer-main.loadbalancer.server.port=9000" # Define um serviço Traefik chamado 'portainer-main'
      - "traefik.http.routers.portainer.service=portainer-main" # O roteador 'portainer' usa o serviço 'portainer-main'
      - "traefik.http.routers.portainer.middlewares=redirect-www-to-main@file,securityHeaders@file,rateLimitMiddleware@file" # Adicionado o middleware para redirecionamento
    # Roteador e Serviço para o endpoint Edge do Portainer (porta 8000)
      - "traefik.http.routers.edge.rule=Host(\`$edge_domain\`) || Host(\`www.$edge_domain\`)"
      - "traefik.http.routers.edge.entrypoints=websecure"
      - "traefik.http.routers.edge.tls=true"
      - "traefik.http.routers.edge.tls.certresolver=lets-encrypt"
      - "traefik.http.services.portainer-edge.loadbalancer.server.port=8000" # Define um serviço Traefik chamado 'portainer-edge'
      - "traefik.http.routers.edge.service=portainer-edge"
      - "traefik.http.routers.edge.middlewares=redirect-www-to-main@file,securityHeaders@file,rateLimitMiddleware@file" # Adicionado o middleware para redirecionamento
    logging:
      options:
        max-size: "10m"
        max-file: "3"   

networks:
  agent_network:
    driver: overlay
    attachable: true
  web:
    external: true
volumes:
  portainer_data:
EOL
    echo -e "${GREEN}✅ docker-swarm.yml criado com sucesso.${NC}"

 ################################
 ##### CRIANDO TRAEFIK.TOML #####
 ################################

# Entra no diretório /docker para criar os arquivos
    cd /docker/traefik || { echo -e "${RED}❌ Não foi possível mudar para o diretório /docker/traefik.${NC}"; exit 1; } 
    
   echo -e "${YELLOW}📝 Criando traefik.toml...${NC}"
    cat <<EOL | sudo tee traefik.toml > /dev/null
[entryPoints]
  [entryPoints.web]
    address = ":80"
    
    [entryPoints.web.http]
      [entryPoints.web.http.redirections]
        [entryPoints.web.http.redirections.entryPoint]
          to = "websecure"
          scheme = "https"
          permanent = true

  [entryPoints.websecure]
    address = ":443"   

[log]
  #level = "WARN"
  level = "INFO"
  filePath = "/var/log/traefik.log"

[accessLog]
  filePath = "/var/log/access.log"

[metrics]
  [metrics.prometheus]
    addEntryPointsLabels = true
    addServicesLabels = true
    addRoutersLabels = true

[api]
  dashboard = true
  debug = false

[certificatesResolvers.lets-encrypt.acme]
  email = "$email"
  storage = "acme.json"
  keyType = "EC256"
  [certificatesResolvers.lets-encrypt.acme.tlsChallenge]

[providers.docker]  
  watch = true
  network = "web"
  exposedByDefault = false
  endpoint = "unix:///var/run/docker.sock"

[providers.file]
  filename = "traefik_dynamic.toml"
  watch = true
EOL
    echo -e "${GREEN}✅ traefik.toml criado com sucesso.${NC}"
    
########################################
##### CRIANDO TRAEFIK_DYNAMIC.TOML #####
########################################

   echo -e "${YELLOW}📝 Criando traefik_dynamic.toml...${NC}"
    cat <<EOL | sudo tee traefik_dynamic.toml > /dev/null
[http.middlewares.simpleAuth.basicAuth]
  users = [
    "$encrypted_password"
  ]

# Use with traefik.http.routers.myRouter.middlewares: "redirect-www-to-main@file"
[http.middlewares]
  [http.middlewares.redirect-www-to-main.redirectregex]
      permanent = true
      regex = "^https?://www\\\\.(.+)"
      replacement = "https://\${1}"

# NOVO: Definição do middleware de segurança de cabeçalhos HTTP
[http.middlewares.securityHeaders.headers]
  browserXssFilter = true
  contentTypeNosniff = true
  frameDeny = true
  sslRedirect = true
  referrerPolicy = "strict-origin-when-cross-origin"  
  contentSecurityPolicy = "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' data: https://fonts.gstatic.com; img-src 'self' data: https:; connect-src 'self' wss: ws:;"
  # HSTS (Strict-Transport-Security) - Descomente se tiver certeza! Força o navegador a usar HTTPS para seu domínio por um período. Cuidado ao habilitar: se o HTTPS quebrar, seus usuários não conseguirão acessar por um tempo.
  strictTransportSecurity = true
  forceSTSHeader = true
  stsPreload = true # Opcional: Para incluir seu domínio na lista de pré-carregamento HSTS dos navegadores. Use com extrema cautela.
  stsSeconds = 31536000 # 1 ano
  stsIncludeSubdomains = true
  customRequestHeaders = [
    "X-Forwarded-Proto: https",
    "X-Forwarded-Port: 443"
  ]
  # Política de permissões
  permissionsPolicy = "geolocation=(), microphone=(), camera=(), speaker=()"
    
[http.middlewares.rateLimitMiddleware.rateLimit]
  burst = 150
  average = 75
  
[http.routers.api]
  rule = "Host(\`$traefik_domain\`) || Host(\`www.$traefik_domain\`)"
  entrypoints = ["websecure"]
  middlewares = ["simpleAuth", "securityHeaders", "rateLimitMiddleware", "redirect-www-to-main"]  
  service = "api@internal"
  [http.routers.api.tls]
    certResolver = "lets-encrypt"
    options = "default@file"

# Configuração SSL/TLS aprimorada
[tls.options]
  [tls.options.default]
    sslStrategies = ["tls.SniStrict"]
    minVersion = "VersionTLS12"
    maxVersion = "VersionTLS13"
    cipherSuites = [
      "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
      "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305",
      "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
      "TLS_RSA_WITH_AES_256_GCM_SHA384",
      "TLS_RSA_WITH_AES_128_GCM_SHA256",
      "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
      "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305",
      "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"
    ]
    curvePreferences = [
      "X25519",
      "secp521r1",
      "secp384r1"
    ]
EOL
    echo -e "${GREEN}✅ traefik_dynamic.toml criado com sucesso.${NC}"

    ####################################
    ##### CERTIFICADOS LETSENCRYPT #####
    ####################################
    
    echo -e "${YELLOW}📝 Configurando permissões para acme.json...${NC}"
    
    if [ ! -f acme.json ]; then
      (sudo touch acme.json && sudo chmod 600 acme.json) > /dev/null 2>&1 & spinner $! 
      wait $!
    fi
    
    echo -e "${GREEN}✅ Permissões para acme.json configuradas.${NC}"

    ###############################
    ##### INICIANDO CONTAINER #####
    ###############################
    
    # Entra no diretório /docker para criar os arquivos

    cd || { echo -e "${RED}❌ Não foi possível mudar para o diretório /docker.${NC}"; exit 1; }

    # Pega o primeiro IP da máquina
    SERVER_IP=$(curl -s ifconfig.me)
    if [ -z "$SERVER_IP" ]; then
        echo -e "${RED}❌ Não foi possível detectar o endereço IP do servidor.${NC}"
        exit 1
    fi

     # Antes de 'sudo docker swarm init...'
    if ! sudo docker info --format '{{.Swarm.LocalNodeState}}' | grep -w -q "active"; then
        echo -e "${YELLOW}🐳 Inicializando Docker Swarm...${NC}"
        (sudo docker swarm init --advertise-addr "$SERVER_IP") > /dev/null 2>&1 & spinner $!
        wait $!
        if [ $? -ne 0 ]; then
            echo -e "${RED}❌ Erro ao inicializar o Docker Swarm.${NC}"
            exit 1
        fi
        echo -e "${GREEN}✅ Docker Swarm inicializado.${NC}"
    else
        echo -e "${GREEN}✅ Docker Swarm já está ativo.${NC}"
    fi

    if ! sudo docker network ls | grep -q "web"; then
    echo -e "${YELLOW}🌐 Criando rede Docker 'web'...${NC}"
    (sudo docker network create --driver=overlay --attachable=true web) > /dev/null 2>&1 & spinner $!
    wait $!
    if [ $? -ne 0 ]; then
        echo -e "${RED}❌ Erro ao criar a rede Docker 'web'.${NC}"
        exit 1
    fi
    echo -e "${GREEN}✅ Rede Docker 'web' criada com sucesso.${NC}"
    else
    echo -e "${GREEN}✅ Rede Docker 'web' já existe.${NC}"
    fi

    cd /docker || { echo -e "${RED}❌ Não foi possível mudar para o diretório /docker.${NC}"; exit 1; }
    
    echo -e "${YELLOW}🚀 Iniciando containers Docker...${NC}"    

    echo -e "${YELLOW}🧹 Verificando e limpando instalações anteriores...${NC}"

   # Passo 1: Verifica se a stack 'loopiin' existe antes de tentar removê-la.
    if [ ! -z "$(sudo docker stack ls --format '{{.Name}}' | grep '^loopiin$')" ]; then
        echo -e "${YELLOW}-> Removendo stack 'loopiin' existente... (Isso pode levar um momento)${NC}"
        sudo docker stack rm loopiin
        
        # PASSO CRÍTICO: Espera ATIVAMENTE a stack ser removida, verificando o status.
        # Este laço 'while' é a única forma garantida de evitar a condição de corrida.
        echo -n -e "${YELLOW}-> Aguardando a finalização completa da remoção${NC}"
        while [ ! -z "$(sudo docker stack ls --format '{{.Name}}' | grep '^loopiin$')" ]; do
            echo -n "."
            sleep 2
        done
        # A quebra de linha garante que a próxima mensagem comece em uma nova linha.
        echo -e "\n${GREEN}✅ Stack anterior removida com sucesso.${NC}"
    else
        echo -e "${GREEN}✅ Nenhuma stack 'loopiin' anterior encontrada.${NC}"
    fi

    # Passo 3: Remove as imagens do Traefik em cache, se existirem.
    if [ ! -z "$(sudo docker images -q traefik)" ]; then
        echo -e "${YELLOW}-> Removendo imagens do Traefik em cache...${NC}"
        (sudo docker rmi $(sudo docker images -q traefik)) > /dev/null 2>&1 & spinner $!
        wait $!
        echo -e "${GREEN}✅ Imagens antigas do Traefik removidas.${NC}"
    fi
    
    (sudo docker stack deploy -c docker-swarm.yml loopiin) > /dev/null 2>&1 & spinner $!
    wait $!    
    if [ $? -ne 0 ]; then
        echo -e "${RED}❌ Erro ao iniciar os containers Docker. Verifique a saída de 'sudo docker stack deploy'.${NC}"
        exit 1
    fi
    echo -e "${GREEN}✅ Containers iniciados com sucesso.${NC}"
    sleep 3
    
    clear
    show_animated_logo

    echo -e "${GREEN}🎉 Instalação concluída com sucesso!${NC}"
    echo -e "${BLUE}📝 Informações de Acesso:${NC}"
    echo -e "${GREEN}================================${NC}"
    echo -e "🔗 Portainer: ${YELLOW}https://$portainer_domain${NC}"
    echo -e "🔗 Traefik: ${YELLOW}https://$traefik_domain${NC}"
    echo -e "${GREEN}================================${NC}"
    echo ""
    echo -e "${BLUE}💡 Dica: Aguarde alguns minutos para que os certificados SSL sejam gerados pelo Let's Encrypt.${NC}"
    echo -e "${BLUE}➡️ Lembre-se de configurar os registros DNS (A/AAAA) para os domínios acima apontarem para este servidor!${NC}"
    echo -e "${GREEN}🌟 Visite: https://loopiin.com.br${NC}"
    echo -e "${BLUE}➡️ Criado por Wallison Santos${NC}"
else
    echo -e "${RED}❌ Instalação cancelada. Por favor, inicie novamente se desejar prosseguir.${NC}"
    exit 0
fi
