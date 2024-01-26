# Atacar un cluster de Kubernetes: dedes un pod a todo el cluster


 Esta basado en el video : https://www.youtube.com/watch?v=iD_klswHJQs


## Enumeración 

Si hacemos una nmap a una IP que tiene una aplicación que está en un cluster:

```console
$ nmap -v <IP>

PORT    STATE SERVICE
22/tcp  open  ssh
80/tcp  open  http

```
Obtendremos los puertos 80/443 de la aplicación y probablemente el puerto 22.

## Establecimiento inicial

Suponer que hemos conseguido abrir un shell en el contenedor aprovechando una vulnerabilidad como inyección de OS o de SQL.

Para ello se puede usar netcat pero hay herramientas interesantes como `pwncat-cs`:
```console
$ sudo pip install pwncat-cs

$ pwncat-cs -lp <LPORT>
```







