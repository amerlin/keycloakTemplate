
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.OpenApi.Models;
using myapp_core.Authentication;
using System.Buffers.Text;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

builder.Services.AddControllers();
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

builder.Services.AddCors(o => o.AddPolicy("MyPolicy", builder =>
{
    builder.AllowAnyOrigin()
           .AllowAnyMethod()
           .AllowAnyHeader();
}));

builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new OpenApiInfo { Title = "MyWebApi", Version = "v1" });

    //First we define the security scheme
    c.AddSecurityDefinition("Bearer", //Name the security scheme
        new OpenApiSecurityScheme
        {
            Description = "JWT Authorization header using the Bearer scheme.",
            Type = SecuritySchemeType.Http, //We set the scheme type to http since we're using bearer authentication
            Scheme = JwtBearerDefaults.AuthenticationScheme //The name of the HTTP Authorization scheme to be used in the Authorization header. In this case "bearer".
        });

    c.AddSecurityRequirement(new OpenApiSecurityRequirement{
                    {
                        new OpenApiSecurityScheme{
                            Reference = new OpenApiReference{
                                Id = JwtBearerDefaults.AuthenticationScheme, //The name of the previously defined security scheme.
                                Type = ReferenceType.SecurityScheme
                            }
                        },new List<string>()
                    }
                });
});

builder.Services.ConfigureJWT(true, "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA5rFptA9z6syRXdkbluHzhHayglriOaSD2yDxZ16hj2nOsc7H0IP6z8pu27IIAeGI50GhA0nx6kt0s4sNhXgdblv7UY8378shDlEOedbcU5xxOM8qPfvuaLhXtIMQw/7wWgQkSnp7g4MG/A0dKsx65gw9AL/Bwqy/wvKxZgMTF3VRIjT6TG7Q/vrXzTOrQ1b7QRp81yZMSaVKcMvhSthd4HtOVhpJavtVZtrp6K16yngiYYtUfcqvEeQoiC9lNegtplI9wTHzWGHJIk/3wv3TZ2KAtVtc5L48i2tWaLiuZRRvHgupQJqtjI0tCJjLpbgkR4XjochnexJjxoFKqLbx2wIDAQAB");

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.UseAuthorization();

app.UseCors("MyPolicy");

app.MapControllers();

app.Run();
