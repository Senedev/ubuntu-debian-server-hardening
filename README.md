
# Ubuntu/Debian Server Hardening

## O que é o script?

Este é um script automatizado para configuração inicial de servidores Ubuntu e Debian. Ele foi projetado para otimizar o processo de instalação, configuração de rede, ajustes de segurança e outras práticas essenciais de administração de sistemas. O script permite que o usuário personalize suas opções de configuração através de parâmetros pré-definidos, oferecendo uma implementação rápida e eficiente para servidores recém-instalados.

## Funcionalidades Principais

O script oferece as seguintes funcionalidades, todas ajustáveis através de variáveis no início do arquivo:

- Atualização do sistema e pacotes.
- Definição de um endereço IP estático.
- Configuração do SSH com ajustes de segurança, como proibição de acesso root, alteração de porta padrão etc.
- Aplicação de políticas de segurança para senhas.
- Bloqueio de dispositivos USB.
- Criptografia de disco e proteção de diretório de boot.
- Remoção de serviços desnecessários.
- Instalação e configuração de Fail2Ban para proteção contra tentativas de login maliciosas.
- Detecção de Rootkits.
- Habilitação de monitoramento de atividades e logs do sistema.
- Reinicialização automática ao final das operações.

## Como Executar

### No Ubuntu ou Debian

1. **Baixar o script:**

   Clone o repositório ou faça o download do script diretamente:

   ```bash
   git clone https://github.com/Senedev/ubuntu-debian-server-hardening.git
   ```

2. **Dar permissão de execução ao script:**

   Navegue até o diretório onde o script está localizado e use o seguinte comando:

   ```bash
   chmod +x autoconfig.sh
   ```

3. **Editar as opções de configuração:**

   O script possui diversas opções de configuração que podem ser personalizadas. Você pode editar essas opções diretamente no início do arquivo `autoconfig.sh` para ajustar conforme suas necessidades.

4. **Executar o script:**

   Para sistemas Ubuntu, use o comando:

   ```bash
   sudo ./autoconfig.sh
   ```

   Para Debian, use:

   ```bash
   ./autoconfig.sh
   ```

5. **Acompanhar as etapas:**

   O script realiza várias operações, como a atualização do sistema, configuração de IP, ajustes de segurança, entre outros. Cada etapa será exibida no terminal para acompanhamento.

## Requisitos

- **Sistema Operacional:** Ubuntu 18.04 ou superior, Debian 10 ou superior.
- **Permissões:** A execução requer privilégios de superusuário (root ou sudo).
