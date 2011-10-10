<?php
  
  $strings['Use this page to set up the connection details for your LDAP or Active Directory server. The user you select here will need access to the user list, so the username and password users log in with can be verified, but no write access is necessary.'] = 'Utilice esta página para establecer los detalles de la conexión para su servidor LDAP o Active Directory. El usuario que aquí seleccione necesitará acceso a la lista de usuarios, para que los usuarios que quieran ingresar sean verificados, pero no es necesario el permiso de escritura.';
  $strings['Important information'] = 'Información importante';
  $strings['When you enable LDAP as your authentication backend in Authentication configuration, you will lose access to all accounts which do not also exist in the LDAP database. This may mean you lose administrative access.'] = 'Cuando LDAP esté habilitado como su método de autenticación en la configuración de autentificación, perderá el acceso a todas las cuentas que no existan en la base de datos de LDAP. Esto quiere decir que perderá los accesos de administración';
  $strings['To resolve this issue, either import all users using the tool on this page and make one an administrator using Users configuration, or create a user with the same username as one in LDAP and make that one an administrator.'] = 'Para resolver este inconveniente, importe todos los usuarios utilizando la herramienta de esta página y haga un único administrador utilizando la configuración de Usuarios, o cree un usuario con el mismo nombre de usuario que haya en LDAP y hagalo administrador.';
  $strings['Hostname'] = 'Nombre de servidor';
  $strings['Use URL syntax (ldap://hostname:port). If your server requires SSL, use ldaps://hostname/ in this field.'] = 'Utilice la sintáxis de URL (ldap://nombre_de_servidor:puerto). Si su servidor solicita SSL, utilice ldaps://nombre_de_servidor/ en este campo';
  $strings['Connection details'] = 'Detalles de conexión';
  $strings['Port'] = 'Puerto';  
  $strings['Warning: The password will be stored unencrypted in the database.'] = 'Atención: La contraseña será almacenada en forma desencriptada en la base de datos.';
  $strings['Base DN'] = 'DN base';
  $strings['This should be the DN string for the OU containing the user list. For example, OU=People,OU=staff,DN=ldap,DN=example,DN=com.'] = 'Esta prodría ser la cadena DN para el OU que contenga la lista de usuarios. Por ejemplo, OU=People, OU=staff,DN=ldap,DN=example,DN=com.';
  $strings['Allowed groups'] = 'Grupos permitidos';
  $strings['You may wish to restrict access to users who belong to certain groups in LDAP. If so, write a comma separated list of group names here. Leave blank to disable this feature.'] = '';
  $strings['Click "%save%" to save the settings'] = 'Haga clic en "%save%" para salvar la configuración';
  $strings['Test connection'] = 'Probar conexión';
  $strings['After configuring and saving your connection settings, you should test your connection to the LDAP server. This test does not check whether the DN can correctly find users, but it will give an indication if The Bug Genie can talk to your LDAP server.'] = 'Luego de configurar y guardar las opciones de conexión, debería probar la conexión con el servidor LDAP. Esta prueba no revisa si el DN puede encontrar usuarios correctamente, pero la dará un indicio si The Bug Genie puede comunicarse con su servidor LDAP.';
  $strings['Import all users'] = 'Importar todos los usuarios';
  $strings["So that you can ensure all users from LDAP exist in The Bug Genie exist for initial configuration (e.g. to set permissions), you can import all users who don't already exist using this tool. If you set a group restriction, this will be obyed here. Remember to make at least one an administrator so you can continue to configure The Bug Genie after switching."] = 'Puede asegurarse de que todos los usuarios de LDAP existan en The Bug Genie en la configuración inicial (por ejemplo, para definir permisos), puede importar todos los usuarios que no existan utilizando esta herramienta. Si define una restricción a un grupo, ésta será aplicada aquí. Recuerde hacer al menos un administrador para poder continuar la configuración de the Bug Genie después de cambiarlo.';
  $strings['Import users'] = 'Importar usuarios';
  $strings['Prune users'] = 'Quitar usuarios';
  $strings["If a user is deleted from LDAP then they will not be able to log into The Bug Genie. However if you want to remove users from The Bug Genie who have been deleted from LDAP you may wish to prune the users list. This action will delete all users from The Bug Genie's user list who do not exist in the LDAP database, and can not be reversed."] = 'Si un usuario es borrado de LDAP entonces no podrá acceder a The Bug Genie. Sin embargo si quiere quitar usuarios de The Bug Genie que han sido eliminados en LDAP puede quitar los usuarios de la lista. Esta acción eliminará todos los usuarios de la lista de The Bug Genie que no existan en la base de datos de LDAP, y no puede deshacerse.';
  $strings['LDAP support is not installed']='El soporte para LDAP no está instalado';
  $strings['The PHP LDAP extension is required to use this functionality. As this module is not installed, all functionality on this page has been disabled.']='La extensión LDAP de PHP es necesaria para activar esta funcionalidad. Como el módulo no está instalado, todas las opciones de esta página han sido inhabilitadas.';
  $strings['Users DN']  = 'DN usuarios';
  $strings['Username attribute']  = 'Atributos del nombre de usuario';
  $strings['This field should contain the name of the attribute where the username is stored, such as uid.']  = 'Este campo debe contener el nombre del atributo en donde el nombre de usuario es guardado, como el uid.';
  $strings['Full name attribute']  = 'Atributo del nombre completo';
  $strings['Email address attribute']  = 'Atributo de la cuenta de correo';
  $strings['Groups DN']  = 'DN grupos';
  $strings['This should be the DN string for the OU containing the group list.']  = 'Esta debe ser la cadena DN para el OU que contiene la lista del grupo.';
  $strings['Group members attribute']  = 'Atributo de los miembros del grupo';
  $strings['This field should contain the name of the attribute where the list of members of a group is stored, such as uniqueMember.']  = 'Este campo debe contener el nombre del atributo donde la lista de miembros de un grupo es almacenado, como uniqueMember.';
  $strings['Please insert the authentication details for a user who can access all LDAP records.'] = 'Por favor inserte los detalles de autentificación de usuario para que pueda acceder a todos los registros de LDAP.';
