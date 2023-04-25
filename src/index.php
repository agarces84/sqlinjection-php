<html>
 <head>
 	<title>SQL injection</title>
 	<style>
 		body{
 		}
 		.user {
 			background-color: yellow;
 		}
 	</style>
 </head>
 
 <body>
 	<h1>PDO vulnerable a SQL injection</h1>
 
 	<?php
	if (isset($_POST["user"]) && isset($_POST["password"])) {
    $dbhost = $_ENV["DB_HOST"];
    $dbname = $_ENV["DB_NAME"];
    $dbuser = $_ENV["DB_USER"];
    $dbpass = $_ENV["DB_PASSWORD"];

    try {
        $pdo = new PDO("mysql:host=$dbhost;dbname=$dbname", $dbuser, $dbpass);
        $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        $username = trim($_POST["user"]);
        $pass = trim($_POST["password"]);

        if (empty($username) || empty($pass)) {
            throw new Exception("Username and password are required.");
        }

        $stmt = $pdo->prepare("SELECT * FROM users WHERE name = :username AND password = SHA2(:pass, 512)");
        $stmt->bindValue(':username', $username);
        $stmt->bindValue(':pass', $pass);
        $stmt->execute();

        if ($stmt->rowCount() >= 1) {
            foreach ($stmt as $user) {
                echo "<div class='user'>Hola " . htmlspecialchars($user["name"], ENT_QUOTES) . " (" . htmlspecialchars($user["role"], ENT_QUOTES) . ").</div>";
            }
        } else {
            echo "<div class='user'>No hi ha cap usuari amb aquest nom o contrasenya.</div>";
        }
    } catch (PDOException $e) {
        echo "<p>ERROR: " . $e->getMessage() . "</p>\n";
    } catch (Exception $e) {
        echo "<p>ERROR: " . $e->getMessage() . "</p>\n";
    }
}
?>
 	
 	<fieldset>
 	<legend>Login form</legend>
  	<form method="post">
		User: <input type="text" name="user" /><br>
		Pass: <input type="text" name="password" /><br>
		<input type="submit" /><br>
 	</form>
  	</fieldset>
	
 </body>
 
 </html>
