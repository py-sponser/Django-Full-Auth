import './App.css';
import QRCode from "react-qr-code";
import {useEffect, useState} from "react";

function App() {
    const [provisionURI, setProvisionURI] = useState(null)

    const getProvisionURI = () => {
        fetch("http://127.0.0.1:8000/accounts/mfa/get-provision-uri/", {
            method: "GET",
            headers: {
                "Content-Type": "application/json",
                "Authorization": "Token 6dfe417849ad42b39b0b530f066903ec34b5eda7",
            },
        })
            .then(response => response.json())
            .then((data) => {
                console.log(data.provision_uri)
                setProvisionURI(data.provision_uri)
            })
    }
    useEffect(() => {
        getProvisionURI()
    }, [])

    return (
    <div className="App">

        <br /><br />
      <QRCode
          value={provisionURI ? provisionURI : "https://google.com"}
          size={256}
      />
    </div>
    );
}

export default App;
