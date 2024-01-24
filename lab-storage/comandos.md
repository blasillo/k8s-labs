

## Crear un volumen persistente

```console

mkdir /mnt/demo

echo "Hola de Kubernetes" > /mnt/demo/index.html
```

Crear un archivo persistent_volume.yaml para definir el volumen:
```yaml

apiVersion: v1    
kind: PersistentVolume
metadata:   
  name: task-pv-volume  
  labels:   
  type: local 
spec:
  storageClassName: manual
  capacity:   
    storage: 2Gi    
  accessModes:
    - ReadWriteMany     
  hostPath: 
    path: "/mnt/demo"

```


```console
kubectl apply -f persistent_volume.yaml
```
## Crear un claim de volumen persistente

Un claim de volumen peristente es una solicitud del volumen creado. 

Se crea un archivo volume_claim.yaml para realizar la solicitud
```yaml
apiVersion: v1    
kind: PersistentVolumeClaim 
metadata: 
  name: task-pv-claim 
spec:
  storageClassName: manual  
  accessModes:
    - ReadWriteMany   
  resources:  
    requests:
      storage: 2Gi
```

```console
kubectl apply -f volume_claim.yaml
```

## Montar el volumen persistente en un pod


Definición de un pod con el almacenamiento pvc_pod.yaml

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: task-pv-pod
spec:
  volumes:
    - name: task-pv-storage
      persistentVolumeClaim:
        claimName: task-pv-claim
  containers:
    - name: task-pv-container
      image: nginx
      ports:
        - containerPort: 80
          name: "http-server"
      volumeMounts:
        - mountPath: "/usr/share/nginx/html"
          name: task-pv-storage
```

Creamos un pod con el volumen persistente:
```console
kubectl apply -f pvc_pod.yaml
```
