# Contenedores Init

 El término "init" se refiere a la palabra inicializar. Los contenedores de inicialización son casos especiales de contenedores en los que queremos ejecutar algunas cargas de trabajo personalizadas, como scripts o comandos, al lanzar nuestro contenedor principal.

En el momento del lanzamiento del contenedor, podemos aprovechar la característica del contenedor de inicialización y lanzar otro contenedor que funcione como un bloque de construcción del contenedor principal y complete la ejecución de la tarea necesaria.

Los contenedores de inicialización son iguales que los contenedores regulares y admiten casi todos los parámetros. Sin embargo, se considera que su ciclo de vida es diferente, ya que se espera que se marquen como completados antes de iniciar el contenedor principal.

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  labels:
    run: nginx
  name: nginx-deploy
spec:
  replicas: 1
  selector:
    matchLabels:
      run: nginx
  template:
    metadata:
      labels:
        run: nginx 
    spec:
      volumes:
      - name: init-volume
        emptyDir: {}
      initContainers:
      - name: busybox
        image: busybox
        volumeMounts:
        - name: init-volume
          mountPath: /nginx-data
        command: ["/bin/sh"]
        args: ["-c", "echo '<h1>Hello Kubernetes Whizlabs</h1>' > /nginx-data/index.html"]
      containers:
      - image: nginx
        name: nginx
        volumeMounts:
        - name: init-volume
          mountPath: /usr/share/nginx/html
```

