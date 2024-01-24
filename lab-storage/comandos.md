

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
