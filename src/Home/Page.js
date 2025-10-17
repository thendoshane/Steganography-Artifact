import './home.css';
import john from '../Images/lucas.jpg';

export default function Page() {
  return (
    <div className="overall" style={{ backgroundImage: `url(${john})` }}>
      <div className="content">
        <h1>Malware Detection Capability</h1>
        <p>
          Explore the <a href="#">Detection System</a> or{' '}
          <a href="#">Find out More</a> about the system and the developers.
        </p>
      </div>
    </div>
  );
}
