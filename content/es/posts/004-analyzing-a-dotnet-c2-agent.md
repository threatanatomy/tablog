+++
title = '004 - Analizando un agente de C2 - Parte 2: el agente'
date = 2023-12-17T12:03:49-05:00
draft = false
translationKey = '004-dotnet-agent'
description = 'In this first part, we will analyze a malicious macro containing an embedded C2 agent. We will analyze how it acts, what techniques it uses to hinder analysis, and how we can obtain indicators of compromise from it.'
cover = "/img/003-procExp.png"
+++


## 1. Introducción

Este post es la continuación de otro donde analizamos una macro maliciosa, que tenía embebido un agente de C2; si aún no lees ese post puedes [hacerlo aquí](/es/posts/003-analyzing-a-dotnet-c2-agent-part1-macro-dropper/)).

En el primer post identificamos que, luego de realizar ciertas técnicas para dificultar su detección, la macro maliciosa extraía y ejecutaba un archivo .exe que estaba embebido como parte del documento malicioso. En este post, analizaremos dicho archivo de manera estática y dinámica para comprender cómo funciona, cómo identificamos que corresponde a un agende de C2, y qué indicadores de compromiso podemos obtener.

> **Disclaimer**: Ejecutar malware en un dispositivo personal/corporativo puede poner en riesgo tu información/la información de tu empresa. Nunca ejecutes malware en un dispositivo que no ha sido específicamente configurado para el análisis.



## 2. Análisis estático del archivo
### 2.1 Identificación de hashes y framework de desarrollo utilizado

Iniciamos el análisis obteniendo el hash del ejecutable:

| Algoritmo | Hash                                                             |
|-----------|------------------------------------------------------------------|
| MD5       | 59211a4e0f27d70c659636746b61945a                                 |
| SHA256    | 2110af4e9c7a4f7a39948cdd696fcd8b 4cdbb7a6a5bf5c5a277b779cc1bf8577 |


Al abrir el binario en PEStudio, podemos identificar algunas cosas interesantes:

![alt text](/img/004-pestudio1.png "PEStudio Analysis")

1. PEStudio identifica el binario como de tipo "Microsoft .NET"
2. El binario parece haber sido compilado el 05 de Setiembre del 2023, por lo que es reciente. (Dicho valor puede ser alterado por lo que no es 100% confiable)
3. Se identifica la ruta del archivo "debug" del binario, la cual contiene \obj\debug, directorio estándar creado por Visual Studio.

Dichos indicadores parecen indicarnos que se trata de un programa .NET; adicionalmente, analizando algunas de las otras secciones de información que ofrece PEStudio podemos obtener mayor información:

![alt text](/img/004-pestudio2.png "PEStudio Indicators")

![alt text](/img/004-pestudio3.png "PEStudio Imports")

1. PEStudio identifica el namespace .NET System.Net.Socket, un indicador más de que es un programa .NET
2. PEStudio identifica una IP, que puede ser un indicador de compromiso (IOC) de interés.
3. PEStudio identifica que el programa, durante su ejecución, importa [clases de .NET](https://learn.microsoft.com/en-us/dotnet/api/?view=net-8.0)

Con dicha información, podemos decir con casi total certeza de que el binario corresponde a uno desarrollado con el framework .NET.

Los archivos desarrollados en .NET son usualmente suceptibles a ser decompilados, debido a que no se compilan directo a lenguaje máquina (los 0 y 1 que entiende la computadora), sino que se compilan en un lenguaje intermedio (llamado Intermediate Language - IL), el cual se compila _durante ejecución_ a lenguaje máquina específico al entorno donde se está ejecutando.

Si bien dicho framework provee flexibilidad, el lenguaje intermedio contiene información sobre los nombres de las clases, métodos, metadata, etc. del programa original, lo que permite ser decompilado y "revertido" casi a código fuente.

Existen distintas herramientas que permiten decompilar un archivo creado en .NET, entre las que se encuentran [_ILSpy_](https://github.com/icsharpcode/ILSpy) y [_dnSpy_](https://github.com/dnSpy/dnSpy); para el presente análisis utilizaré _dnSpy_ debido a las capacidades de debugging que ofrece.

### 2.2 Análisis inicial del binario

Al abrir el ejecutable en _dnSpy_, validamos que efectivamente podemos visualizar el código:

![alt text](/img/004-dnspy.png "dnSpy")

Dado que analizar cada función que llama el ejecutable puede ser muy tedioso, seguiremos el flujo de llamadas que se hacen desde el método Main.

1. Cuando el programa se inicia llama al formulario Form1, el cual, al iniciarse llama al método **InitializeComponent()**
2. El método InitializeComponent() se crea automáticamente al momento de crear un formulario; de este método podemos destacar dos cosas: se configura la opacidad del formulario a 0 para hacer de este invisible, y se llama al método **Form1_Load**:

```c#
private void InitializeComponent()
		{
            ...
			base.Name = "Form1";
			base.Opacity = 0.0;
			base.ShowIcon = false;
			base.ShowInTaskbar = false;
			this.Text = "Form1";
			base.FormClosing += this.Form1_FormClosing;
			base.Load += this.Form1_Load;
            ...

		}
```
3. El método **Form1_Load** detiene la ejecución ("duerme") por unos segundos antes de llamar al método **corediQart()** de la clase **MIETDIM**:

```c#
private void Form1_Load(object sender, EventArgs e)
		{
			try
			{
				Thread.Sleep(1010);
				base.ShowInTaskbar = false;
				base.Visible = false;
				base.FormBorderStyle = FormBorderStyle.SizableToolWindow;
				Thread.Sleep(2050);
				Thread.Sleep(1280);
				this.mainvp.corediQart();
			}
			catch
			{
			}
		}
```
4. El método **corediQart()** realiza las siguientes acciones:
    4.1 Asigna el primer puerto definido en la variable _ports_ a la variable _port_
    4.2 Obtiene el nombre de la computadora donde se está ejecutando, así como el usuario que está ejecutando el programa y lo asigna a la variable _userAiunt_
    4.3 Crea un objeto de tipo _TimerCallback_ que llama al método **procvQloop**
    4.4 Configura el objeto de tipo _TimerCallback_ para que se ejecute cada 58.51 segundos, luego de esperar inicialmente 49.12 segundos.

```c#
		public void corediQart()
		{
			DIRERRIF.port = DIRERRIF.ports[0];
			this.userAiunt = new MRDFINF();
			this.hdbiAve.corweavr = this;
			TimerCallback callback = new TimerCallback(this.procvQloop);
			Timer timer = new Timer(callback, this.objeAdate, 49120, 58510);
			this.objeAdate.timer = timer;
		}
        public static int[] ports = new int[]
		{
			9149,
			15198,
			17818,
			27781,
			29224
		};
        public MRDFINF()
		{
			this.rim_veoion = "N._D._2.0".Replace("_", "");
			this.comtname = SystemInformation.ComputerName;
			this.acc_datQtime = Environment.UserName;
			this.accounQname = "";
			this.lanrinfo = "";
		}

```

5. Analizando lo que hace el método **procvQloop**, inicia una conexión TCP con la IP almacenada en la variable _min\_codns_; en dicha variable, la IP se encuentra almacenada como un conjunto de bytes, probablemente para dificultar su detección:

![alt text](/img/004-ipbytes.png "IP as bytes")

La conexión TCP se realiza con la IP almacenada en la variable _min\_codns_ en el puerto asignado a la variable _port_.

6. Una vez realizada la conexión, si es exitosa, se llama al método **procD_core()**, el cual realiza múltiples operaciones:
    6.1 Obtiene una respuesta de la conexión TCP establecida previamente
    6.2 Como parte de la respuesta espera que el tamaño de la comunicación se especifique en los primeros 5 bytes del stream de datos, el cual utiliza para obtener el resto de la data de la conexión en bloques de 1024 bytes
    6.3 Separa la respuesta obtenida utilizando el separador '='
    6.4 En base al primer valor de la respuesta (lo que estaba antes del '=') llama a distintos métodos.

![alt text](/img/004-GetCommand.png "Parsing response")

![alt text](/img/004-ParseResponse.png "Execute actions")

Sin analizar el resto de las funciones, el comportamiento del programa ya nos hace suponer que puede ser un agente de C2:

1. Cada cierto tiempo (aproximadamente cada minuto), se comunica con un servidor basado en una IP y un puerto no común.
2. Recibe respuesta del servidor, la cual se compone de dos secciones.
3. En base a la primera sección (comandos), llama a métodos pasándoles la segunda sección (payload/parámetros del comando).

En base a dicho análisis podemos asumir que el servidor envía comandos al agente, el cual los ejecuta. Posterior análisis nos permitirá confirmar si realmente es un agente de Comando y Control, así como las capacidades que tiene este agente.

### 2.3 Análisis de los métodos del agente de C2

Debido a que analizar cada función sería muy tedioso, analizaremos algunas funciones que me parecieron interesantes:

#### 2.3.1 Listar procesos

Al igual que en la macro que contenía el binario, se visualiza el uso de subguiones para separar comandos/variables:

![alt text](/img/004-lp1.png "Obfuscation")

Al recibir el comando "geyTtavs", se obtienen los procesos que se están ejecutando en el sistema y se envía el ID y nombre de estos mediante la función **loadQData**:

![alt text](/img/004-lp2.png "List Processes")

La función **loadQData** envía el tipo de respuesta a esperar, el tamaño de esta y la respuesta al servidor.

Con solo analizar dicha función, podemos confirmar que es un agente de Comando y Control: el programa se contacta a un servidor, recibe una instrucción (listar procesos en este caso) y la envía de vuelta al servidor.

#### 2.3.2 Establecer persistencia

La llave de registro _HKEY\_CURRENT\_USER\Software\Microsoft\Windows\CurrentVersion\Run_ es usualmente abusada por atacantes para establecer persistencia; dicha técnica está [catalogada en MITRE ATT&CK con ID T1547.001](https://attack.mitre.org/techniques/T1547/001/) y [permite a un atacante ejecutar un programa cuando el usuario inicia sesión](https://learn.microsoft.com/en-us/windows/win32/setupapi/run-and-runonce-registry-keys), bajo el contexto (permisos) de ese usuario.

Verificamos que el agente ofrece la capacidad de establecer persistencia, al recibir el comando "puyTtsrt" crea la llave de registro con nombre "haijwivetsgVr":

![alt text](/img/004-pers1.png "Establish persistence 1")

![alt text](/img/004-pers2.png "Establish persistence 2")

![alt text](/img/004-pers3.png "Establish persistence 3")

Al igual que antes, vemos que el nombre de la ruta en el registro ha sido dividido utilizando subguiones para dificultar su identificación.


#### 2.3.3 Listar archivos

Al recibir el comando "flyTes" junto con una ruta, el comando lista los archivos de la ruta utilizando el método **Directory.GetFiles**, los concatena utilizando el caracter '>' como separador y los envía al servidor:

![alt text](/img/004-listfiles.png "Listing files")

![alt text](/img/004-listfiles2.png "Read directory")

