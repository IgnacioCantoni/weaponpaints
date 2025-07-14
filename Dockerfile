# Usamos imagen oficial de PHP con Apache
FROM php:8.2-apache

# Activar extensiones necesarias: pdo_mysql y curl
RUN docker-php-ext-install pdo_mysql && docker-php-ext-enable pdo_mysql

# Habilitar mod_rewrite de Apache (común en proyectos PHP)
RUN a2enmod rewrite

# Copiamos el contenido del proyecto al directorio raíz web de Apache
COPY . /var/www/html/

# Establecemos permisos adecuados (opcional, depende de tu proyecto)
RUN chown -R www-data:www-data /var/www/html

# Exponer el puerto 80 (HTTP)
EXPOSE 80

# Comando por defecto para iniciar Apache en foreground
CMD ["apache2-foreground"]
