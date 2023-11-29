import logo from './logo.svg';
import './App.css';
import KeyCloakService from './security/KeycloakService';
import HttpService from './service/HttpService';

const logout = () =>{
  KeyCloakService.CallLogout();
}

function weather() {
  HttpService.getAxiosClient()
    .get("https://localhost:7202/WeatherForecast")
    .then(
      (p) => alert(JSON.stringify(p.data)),
      (e) => alert(e.message)
    );
}

function values() {
  HttpService.getAxiosClient()
    .get("https://localhost:7202/Values")
    .then(
      (p) => alert(JSON.stringify(p.data)),
      (e) => alert(e.message)
    );
}


function App() {
  return (
    <div className="App">
      <header className="App-header">
        <img src={logo} className="App-logo" alt="logo" />
        <p>Welcome: {KeyCloakService.GetUserName()}</p>
        <p>Roles: {KeyCloakService.GetUserRoles()?.join(" ")}</p>
        <br/><br/>
        <button onClick={weather}>WeatherCast</button>
        <button onClick={values}>Values</button>
        <br/><br/>
        <p><button onClick={logout}>Logout</button></p>
      </header>
    </div>
  );
}

export default App;
