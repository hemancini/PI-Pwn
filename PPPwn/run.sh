#!/bin/bash

LOG_COMMAND="sudo tee /dev/tty1 | sudo tee /dev/pts/* | sudo tee -a /boot/firmware/PPPwn/pwn.log"

if [ -f /boot/firmware/PPPwn/config.sh ]; then
	source /boot/firmware/PPPwn/config.sh
fi
if [ -z $PYPWN ]; then PYPWN=false; fi
if [ $PYPWN = true ]; then
	sudo bash /boot/firmware/PPPwn/runpy.sh
	exit 0
fi
if [ -f /boot/firmware/PPPwn/pconfig.sh ]; then
	source /boot/firmware/PPPwn/pconfig.sh
fi

if [ -z $INTERFACE ]; then INTERFACE="eth0"; fi              # Interfaz de red
if [ -z $FIRMWAREVERSION ]; then FIRMWAREVERSION="11.00"; fi # Versión de firmware PS4
if [ -z $SHUTDOWN ]; then SHUTDOWN=true; fi                  # Apagar al finalizar
if [ -z $USBETHERNET ]; then USBETHERNET=false; fi           # Usar adaptador USB Ethernet
if [ -z $PPPOECONN ]; then PPPOECONN=false; fi               # Establecer conexión PPPoE
if [ -z $VMUSB ]; then VMUSB=false; fi                       # Habilitar USB virtual
if [ -z $DTLINK ]; then DTLINK=false; fi                     # Habilitar servicio dtlink
if [ -z $PPDBG ]; then PPDBG=false; fi                       # Modo debug
if [ -z $TIMEOUT ]; then TIMEOUT="5m"; fi                    # Tiempo máximo de ejecución
if [ -z $RESTMODE ]; then RESTMODE=false; fi                 # Modo de comprobación previa
if [ -z $LEDACT ]; then LEDACT="normal"; fi                  # Comportamiento de LEDs
if [ -z $XFWAP ]; then XFWAP="1"; fi                         # Tiempo espera tras PIN
if [ -z $XFGD ]; then XFGD="4"; fi                           # Retardo de preparación (groom)
if [ -z $XFBS ]; then XFBS="0"; fi                           # Tamaño de buffer
if [ -z $XFSN ]; then XFSN="0x1000"; fi                      # Número de sprays para el exploit
if [ -z $XFPN ]; then XFPN="0x1000"; fi                      # Número de pins para el exploit
if [ -z $XFCN ]; then XFCN="0x1"; fi                         # Número de intentos de corrupción
if [ -z $XFNWB ]; then XFNWB=false; fi                       # No esperar paquete PADI
if [ -z $OIPV ]; then OIPV=false; fi                         # Usar IP alternativa
if [ -z $UGH ]; then UGH=true; fi                            # Usar payload GoldHEN
if [ -z $ENABLED ]; then ENABLED=true; fi                    # Habilitar el script

# Seleccionar dirección IPv6 según configuración
if [ $OIPV = true ]; then
	XFIP="fe80::4141:4141:4141:4141" # IP alternativa
else
	XFIP="fe80::9f9f:41ff:9f9f:41ff" # IP predeterminada
fi

# Configurar parámetro de espera PADI según configuración
if [ $XFNWB = true ]; then
	XFNW="--no-wait-padi"
else
	XFNW=""
fi

# Establecer valores iniciales para archivos stage2 y directorio
STA2="stage2_1100.bin" # Archivo stage2 predeterminado
HDIR="vx_sta/"         # Directorio para payloads

# Seleccionar stage2 y directorio según versión de firmware y modo GoldHEN
if [ $UGH = true ] && [[ $FIRMWAREVERSION == "9.00" ]] || [[ $FIRMWAREVERSION == "9.03" ]] || [[ $FIRMWAREVERSION == "9.60" ]] || [[ $FIRMWAREVERSION == "10.00" ]] || [[ $FIRMWAREVERSION == "10.01" ]] || [[ $FIRMWAREVERSION == "10.50" ]] || [[ $FIRMWAREVERSION == "10.70" ]] || [[ $FIRMWAREVERSION == "10.71" ]] || [[ $FIRMWAREVERSION == "11.00" ]]; then
	HDIR="gh_sta/" # Directorio para GoldHEN
	# Seleccionar archivo stage2 específico para cada versión con GoldHEN
	if [[ $FIRMWAREVERSION == "9.00" ]]; then
		STA2="stage2_900.bin"
	elif [[ $FIRMWAREVERSION == "9.03" ]]; then
		STA2="stage2_903.bin"
	elif [[ $FIRMWAREVERSION == "9.60" ]]; then
		STA2="stage2_950.bin"
	elif [[ $FIRMWAREVERSION == "10.00" ]] || [[ $FIRMWAREVERSION == "10.01" ]]; then
		STA2="stage2_1000.bin"
	elif [[ $FIRMWAREVERSION == "10.50" ]] || [[ $FIRMWAREVERSION == "10.70" ]] || [[ $FIRMWAREVERSION == "10.71" ]]; then
		STA2="stage2_1050.bin"
	elif [[ $FIRMWAREVERSION == "11.00" ]]; then
		STA2="stage2_1100.bin"
	fi
else
	UGH=false
	# Seleccionar archivo stage2 específico para cada versión sin GoldHEN
	if [[ $FIRMWAREVERSION == "7.00" ]] || [[ $FIRMWAREVERSION == "7.01" ]] || [[ $FIRMWAREVERSION == "7.02" ]]; then
		STA2="stage2_700.bin"
	elif [[ $FIRMWAREVERSION == "7.50" ]] || [[ $FIRMWAREVERSION == "7.51" ]] || [[ $FIRMWAREVERSION == "7.55" ]]; then
		STA2="stage2_750.bin"
	elif [[ $FIRMWAREVERSION == "8.00" ]] || [[ $FIRMWAREVERSION == "8.01" ]] || [[ $FIRMWAREVERSION == "8.03" ]]; then
		STA2="stage2_800.bin"
	elif [[ $FIRMWAREVERSION == "8.50" ]] || [[ $FIRMWAREVERSION == "8.52" ]]; then
		STA2="stage2_8.50.bin"
	elif [[ $FIRMWAREVERSION == "9.00" ]]; then
		STA2="stage2_900.bin"
	elif [[ $FIRMWAREVERSION == "9.03" ]] || [[ $FIRMWAREVERSION == "9.04" ]]; then
		STA2="stage2_903.bin"
	elif [[ $FIRMWAREVERSION == "9.50" ]] || [[ $FIRMWAREVERSION == "9.51" ]] || [[ $FIRMWAREVERSION == "9.60" ]]; then
		STA2="stage2_950.bin"
	elif [[ $FIRMWAREVERSION == "10.00" ]] || [[ $FIRMWAREVERSION == "10.01" ]]; then
		STA2="stage2_1000.bin"
	elif [[ $FIRMWAREVERSION == "10.50" ]] || [[ $FIRMWAREVERSION == "10.70" ]] || [[ $FIRMWAREVERSION == "10.71" ]]; then
		STA2="stage2_1050.bin"
	elif [[ $FIRMWAREVERSION == "11.00" ]]; then
		STA2="stage2_1100.bin"
	fi
fi

# Detectar modelo de Raspberry Pi y configurar binario apropiado
PITYP=$(tr -d '\0' </proc/device-tree/model) # Obtener modelo de Raspberry Pi
if [[ $PITYP == *"Raspberry Pi 2"* ]]; then
	coproc read -t 15 && wait "$!" || true # Esperar 15 segundos
	CPPBIN="pppwn7"                        # Binario para Pi 2
	VMUSB=false
elif [[ $PITYP == *"Raspberry Pi 3"* ]]; then
	coproc read -t 10 && wait "$!" || true # Esperar 10 segundos
	CPPBIN="pppwn64"                       # Binario para Pi 3
	VMUSB=false
elif [[ $PITYP == *"Raspberry Pi 4"* ]]; then
	coproc read -t 5 && wait "$!" || true # Esperar 5 segundos
	CPPBIN="pppwn64"                      # Binario para Pi 4
elif [[ $PITYP == *"Raspberry Pi Compute Module 4"* ]]; then
	coproc read -t 5 && wait "$!" || true # Esperar 5 segundos
	CPPBIN="pppwn64"                      # Binario para CM4
elif [[ $PITYP == *"Raspberry Pi 5"* ]]; then
	coproc read -t 5 && wait "$!" || true # Esperar 5 segundos
	CPPBIN="pppwn64"                      # Binario para Pi 5
elif [[ $PITYP == *"Raspberry Pi Zero 2"* ]]; then
	coproc read -t 8 && wait "$!" || true # Esperar 8 segundos
	CPPBIN="pppwn64"                      # Binario para Pi Zero 2
	VMUSB=false
elif [[ $PITYP == *"Raspberry Pi Zero"* ]]; then
	coproc read -t 10 && wait "$!" || true # Esperar 10 segundos
	CPPBIN="pppwn11"                       # Binario para Pi Zero
	VMUSB=false
elif [[ $PITYP == *"Raspberry Pi"* ]]; then
	coproc read -t 15 && wait "$!" || true # Esperar 15 segundos
	CPPBIN="pppwn11"                       # Binario para otros Pi
	VMUSB=false
else
	coproc read -t 5 && wait "$!" || true # Esperar 5 segundos
	CPPBIN="pppwn64"                      # Binario por defecto
	VMUSB=false
fi

# Ajustar binario según arquitectura del sistema
arch=$(getconf LONG_BIT)
if [ $arch -eq 32 ] && [ $CPPBIN = "pppwn64" ] && [[ ! $PITYP == *"Raspberry Pi 4"* ]] && [[ ! $PITYP == *"Raspberry Pi 5"* ]]; then
	CPPBIN="pppwn7" # Usar binario de 32 bits en sistemas de 32 bits
fi

# Configuración de LEDs
PLED=""
ALED=""
if [[ $LEDACT == "status" ]] || [[ $LEDACT == "off" ]]; then
	# Detectar rutas de LEDs según modelo
	if [ -f /sys/class/leds/PWR/trigger ] && [ -f /sys/class/leds/ACT/trigger ]; then
		PLED="/sys/class/leds/PWR/trigger"    # LED de energía
		ALED="/sys/class/leds/ACT/trigger"    # LED de actividad
		echo none | sudo tee $PLED >/dev/null # Apagar LED de energía
		echo none | sudo tee $ALED >/dev/null # Apagar LED de actividad
	elif [ -f /sys/class/leds/user-led1/trigger ] && [ -f /sys/class/leds/user-led2/trigger ]; then
		PLED="/sys/class/leds/user-led1/trigger" # LED 1 alternativo
		ALED="/sys/class/leds/user-led2/trigger" # LED 2 alternativo
		echo none | sudo tee $PLED >/dev/null    # Apagar LED 1
		echo none | sudo tee $ALED >/dev/null    # Apagar LED 2
	else
		LEDACT="normal" # Usar comportamiento normal si no hay LEDs disponibles
	fi
fi

# Configurar servicios según las opciones
start_services() {
	if [ $PPPOECONN = true ]; then
		sudo systemctl start pppoe
		if [ $DTLINK = true ]; then
			sudo systemctl start dtlink
		fi
	else
		if [ $SHUTDOWN = true ]; then
			coproc read -t 5 && wait "$!" || true
			sudo poweroff
		else
			if [ $DTLINK = true ]; then
				sudo systemctl start dtlink
			else
				sudo ip link set $INTERFACE down
			fi
		fi
	fi
	exit 0
}

echo -e "\n\n\033[36m _____  _____  _____                               
|  __ \\|  __ \\|  __ \\                    _     _   
| |__) | |__) | |__) |_      ___ __    _| |_ _| |_ 
|  ___/|  ___/|  ___/\\ \\ /\\ / / '_ \\  |_   _|_   _|
| |    | |    | |     \\ V  V /| | | |   |_|   |_|  
|_|    |_|    |_|      \\_/\\_/ |_| |_|\033[0m
\n\033[33mhttps://github.com/TheOfficialFloW/PPPwn\nhttps://github.com/xfangfang/PPPwn_cpp\033[0m\n" | $LOG_COMMAND

# Detener servicios que puedan interferir
sudo systemctl stop pppoe
sudo systemctl stop dtlink

# Configurar interfaz de red
if [ $USBETHERNET = true ]; then
	# Reiniciar adaptador USB Ethernet
	echo '1-1' | sudo tee /sys/bus/usb/drivers/usb/unbind >/dev/null
	coproc read -t 1 && wait "$!" || true
	echo '1-1' | sudo tee /sys/bus/usb/drivers/usb/bind >/dev/null
	coproc read -t 4 && wait "$!" || true
	sudo ip link set $INTERFACE up
else
	# Reiniciar interfaz Ethernet estándar
	sudo ip link set $INTERFACE down
	coproc read -t 5 && wait "$!" || true
	sudo ip link set $INTERFACE up
fi

echo -e "\n\033[36m$PITYP\033[92m\nFirmware:\033[93m $FIRMWAREVERSION\033[92m\nInterface:\033[93m $INTERFACE\033[0m" | sudo tee /dev/tty1
echo -e "\033[92mPPPwn:\033[93m C++ $CPPBIN \033[0m" | sudo tee /dev/tty1

# Configurar dispositivo USB virtual si está habilitado
if [ $VMUSB = true ]; then
	sudo rmmod g_mass_storage
	FOUND=0
	# Buscar unidades con directorio "payloads"
	readarray -t rdirarr < <(sudo ls /media/pwndrives)
	for rdir in "${rdirarr[@]}"; do
		readarray -t pdirarr < <(sudo ls /media/pwndrives/${rdir})
		for pdir in "${pdirarr[@]}"; do
			if [[ ${pdir,,} == "payloads" ]]; then
				FOUND=1
				UDEV='/dev/'${rdir}
				break
			fi
		done
		if [ "$FOUND" -ne 0 ]; then
			break
		fi
	done
	# Activar modo almacenamiento masivo USB
	if [[ ! -z $UDEV ]]; then
		sudo modprobe g_mass_storage file=$UDEV stall=0 ro=0 removable=1
	fi
	echo -e "\033[92mUSB Drive:\033[93m Enabled\033[0m" | $LOG_COMMAND
fi

if [ $PPPOECONN = true ]; then
	echo -e "\033[92mInternet Access:\033[93m Enabled\033[0m" | $LOG_COMMAND
else
	echo -e "\033[92mInternet Access:\033[93m Disabled\033[0m" | $LOG_COMMAND
fi

if [ -f /boot/firmware/PPPwn/pwn.log ]; then
	sudo rm -f /boot/firmware/PPPwn/pwn.log
fi

# Configurar LED de estado si está habilitado
if [[ $LEDACT == "status" ]]; then
	echo timer | sudo tee $PLED >/dev/null
fi

if [[ ! $(ifconfig $INTERFACE) == *"RUNNING"* ]]; then
	echo -e "\033[31mWaiting for link\033[0m" | $LOG_COMMAND
	while [[ ! $(ifconfig $INTERFACE) == *"RUNNING"* ]]; do
		coproc read -t 2 && wait "$!" || true
	done
	echo -e "\033[32mLink found\033[0m" | $LOG_COMMAND
fi

# Modo de verificación de GoldHEN previamente instalado
if [ $RESTMODE = true ] && [ $UGH = true ]; then
	# Iniciar servidor PPPoE para verificar
	sudo pppoe-server -I $INTERFACE -T 60 -N 1 -C PPPWN -S PPPWN -L 192.168.2.1 -R 192.168.2.2
	coproc read -t 2 && wait "$!" || true

	# Esperar a que el puerto 3232 (GoldHEN) esté disponible
	while [[ $(sudo nmap -p 3232 192.168.2.2 | grep '3232/tcp' | cut -f2 -d' ') == "" ]]; do
		coproc read -t 2 && wait "$!" || true
	done
	coproc read -t 5 && wait "$!" || true

	if [ $ENABLED = false ]; then
		echo -e "\033[95mPPPwn disabled, exiting...\033[0m\n" | $LOG_COMMAND
		start_services
	fi

	# Verificar si GoldHEN ya está instalado
	GHT=$(sudo nmap -p 3232 192.168.2.2 | grep '3232/tcp' | cut -f2 -d' ')
	if [[ $GHT == *"open"* ]]; then
		# GoldHEN ya está instalado, no es necesario ejecutar PPPwn
		echo -e "\033[95mGoldhen found aborting pppwn\033[0m\n" | $LOG_COMMAND
		if [[ $LEDACT == "status" ]]; then
			echo none | sudo tee $PLED >/dev/null
			echo default-on | sudo tee $ALED >/dev/null
		fi
		sudo killall pppoe-server
		start_services
	else
		# GoldHEN no está instalado, continuar con PPPwn
		echo -e "\n\033[95mGoldhen not found starting pppwn\033[0m\n" | $LOG_COMMAND
		sudo killall pppoe-server

		# Reiniciar interfaz de red
		if [ $USBETHERNET = true ]; then
			echo '1-1' | sudo tee /sys/bus/usb/drivers/usb/unbind >/dev/null
			coproc read -t 1 && wait "$!" || true
			echo '1-1' | sudo tee /sys/bus/usb/drivers/usb/bind >/dev/null
			coproc read -t 4 && wait "$!" || true
			sudo ip link set $INTERFACE up
		else
			sudo ip link set $INTERFACE down
			coproc read -t 5 && wait "$!" || true
			sudo ip link set $INTERFACE up
		fi
	fi
fi

# Mostrar dirección IP si está disponible
PIIP=$(hostname -I) || true
if [ "$PIIP" ]; then
	echo -e "\n\033[92mIP: \033[93m $PIIP\033[0m" | $LOG_COMMAND
fi

echo -e "\n\033[95mReady for console connection\033[0m\n" | $LOG_COMMAND

# Bucle principal de ejecución del exploit
while [ true ]; do

	if [[ $LEDACT == "status" ]]; then
		echo heartbeat | sudo tee $PLED >/dev/null
		echo timer | sudo tee $ALED >/dev/null
	fi

	if [ -f /boot/firmware/PPPwn/config.sh ]; then
		if grep -Fxq "PPDBG=true" /boot/firmware/PPPwn/config.sh; then
			PPDBG=true
		else
			PPDBG=false
		fi
	fi

	# Ejecutar el binario PPPwn y procesar su salida línea por línea
	while read -r stdo; do
		if [ $PPDBG = true ]; then
			echo -e $stdo | sudo tee /dev/tty1 | sudo tee /dev/pts/* | sudo tee -a /boot/firmware/PPPwn/pwn.log
		fi

		# Detectar resultados y eventos específicos
		if [[ $stdo == "[+] Done!" ]]; then
			# Exploit exitoso
			echo -e "\033[32m\nConsole PPPwned! \033[0m\n" | $LOG_COMMAND
			if [[ $LEDACT == "status" ]]; then
				echo none | sudo tee $PLED >/dev/null
				echo default-on | sudo tee $ALED >/dev/null
			fi
			start_services

		elif [[ $stdo == *"Scanning for corrupted object...failed"* ]]; then
			echo -e "\033[31m\nFailed retrying...\033[0m\n" | $LOG_COMMAND
		elif [[ $stdo == *"Unsupported firmware version"* ]]; then
			echo -e "\033[31m\nUnsupported firmware version\033[0m\n" | $LOG_COMMAND
			if [[ $LEDACT == "status" ]]; then
				echo none | sudo tee $ALED >/dev/null
				echo default-on | sudo tee $PLED >/dev/null
			fi
			exit 1
		elif [[ $stdo == *"Cannot find interface with name of"* ]]; then
			echo -e "\033[31m\nInterface $INTERFACE not found\033[0m\n" | $LOG_COMMAND
			if [[ $LEDACT == "status" ]]; then
				echo none | sudo tee $ALED >/dev/null
				echo default-on | sudo tee $PLED >/dev/null
			fi
			exit 1
		fi
	done < <(timeout $TIMEOUT sudo /boot/firmware/PPPwn/$CPPBIN --interface "$INTERFACE" --fw "${FIRMWAREVERSION//./}" -sta "$HDIR$STA2" --ipv "$XFIP" --wait-after-pin $XFWAP --groom-delay $XFGD --buffer-size $XFBS --spray-num $XFSN --pin-num $XFPN --corrupt-num $XFCN $XFNW)

	# Configurar LEDs tras la ejecución
	if [[ $LEDACT == "status" ]]; then
		echo none | sudo tee $ALED >/dev/null
		echo default-on | sudo tee $PLED >/dev/null
	fi

	# Reiniciar interfaz de red para siguiente intento
	sudo ip link set $INTERFACE down
	coproc read -t 3 && wait "$!" || true
	sudo ip link set $INTERFACE up
done
