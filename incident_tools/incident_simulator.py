"""
Incident Simulator

Author:
Andrew Piggot

Purpose: 
Simulate production-like failure scenarios for incident response training

Usage: 
Educational purposes, incident response drills, chaos engineering
"""

import os
import sys
import time
import random
import threading
import subprocess
import tempfile
import socket
from typing import Dict, List, Optional, Tuple
from datetime import datetime, timedelta
import json

# Main class for simulating various production incidents
class IncidentTool:
    
    def __init__( self ):
        self.active_sims = {}
        self.sim_history = []
        self.temp_files = []
        self.temp_processes = []
        self.scenarios = {
            'cpu_spike': {
                'name': 'High CPU Usage',
                'description': 'Simulates sustained high CPU load',
                'severity': 'High',
                'duration': '30-300 seconds'
            },
            'memory_leak': {
                'name': 'Memory Leak',
                'description': 'Gradually consumes available RAM',
                'severity': 'Critical',
                'duration': '60-600 seconds'
            },
            'disk_fill': {
                'name': 'Disk Space Exhaustion',
                'description': 'Fills up disk space rapidly',
                'severity': 'Critical',
                'duration': 'Until stopped'
            },
            'dns_failure': {
                'name': 'DNS Resolution Failure',
                'description': 'Blocks DNS queries to simulate network issues',
                'severity': 'High',
                'duration': '30-180 seconds'
            },
            'port_exhaust': {
                'name': 'Port Exhaustion',
                'description': 'Opens many connections to exhaust available ports',
                'severity': 'High',
                'duration': '60-300 seconds'
            },
            'io_storm': {
                'name': 'I/O Storm',
                'description': 'Creates heavy disk I/O activity',
                'severity': 'Medium',
                'duration': '30-240 seconds'
            },
            'network_lag': {
                'name': 'Network Latency',
                'description': 'Simulates network delays and packet loss',
                'severity': 'Medium',
                'duration': '60-300 seconds'
            },
            'process_bomb': {
                'name': 'Process Fork Bomb',
                'description': 'Creates many processes to consume system resources',
                'severity': 'Critical',
                'duration': '10-60 seconds'
            }
        }
    
    # Start an incident simulation
    def StartSim( self, scenario: str, duration: int = None, intensity: str = 'medium' ) -> Dict:
        if scenario not in self.scenarios:
            return {'error': f'Unknown scenario: {scenario}'}
        
        if scenario in self.active_sims:
            return {'error': f'Scenario {scenario} is already running'}
        
        print( f"\n{'='*60}" )
        print( f"STARTING INCIDENT SIMULATION" )
        print( f"{'='*60}" )
        print( f"Scenario: {self.scenarios[scenario]['name']}" )
        print( f"Description: {self.scenarios[scenario]['description']}" )
        print( f"Severity: {self.scenarios[scenario]['severity']}" )
        print( f"Intensity: {intensity.upper()}")
        
        start_time = datetime.now()
        
        try:
            if scenario == 'cpu_spike':
                result = self._SimCPU( duration or 60, intensity )
            elif scenario == 'memory_leak':
                result = self._SimMemory( duration or 120, intensity )
            elif scenario == 'disk_fill':
                result = self._SimDisk( duration or 300, intensity )
            elif scenario == 'dns_failure':
                result = self._SimDNS( duration or 90, intensity )
            elif scenario == 'port_exhaust':
                result = self._SimPorts( duration or 180, intensity )
            elif scenario == 'io_storm':
                result = self._SimIO( duration or 120, intensity )
            elif scenario == 'network_lag':
                result = self._SimNetwork( duration or 150, intensity )
            elif scenario == 'process_bomb':
                result = self._SimProcesses( duration or 30, intensity )
            else:
                return {'error': 'Simulation not implemented'}
            
            # Record simulation
            sim_record = {
                'scenario': scenario,
                'start_time': start_time.isoformat(),
                'end_time': datetime.now().isoformat(),
                'duration': duration,
                'intensity': intensity,
                'result': result
            }
            self.sim_history.append( sim_record )
            
            print( f"\nSimulation completed!" )
            print( f"Duration: {( datetime.now( ) - start_time ).seconds} seconds" )
            
            return result
            
        except Exception as e:
            return {'error': f'Simulation failed: {str( e )}'}
    
    # Simulate high CPU usage
    def _SimCPU( self, duration: int, intensity: str ) -> Dict:
        print( f"Simulating high CPU usage for {duration} seconds..." )
        
        # Determine number of threads based on intensity
        if intensity == 'low':
            threads = 1
        elif intensity == 'medium':
            threads = 2
        else:  # high
            threads = 4
        
        stop_event = threading.Event()
        
        def cpu_burn():
            while not stop_event.is_set():
                # Busy loop to consume CPU
                for _ in range( 1000000 ):
                    if stop_event.is_set():
                        break
                    _ = sum( range( 100 ) )
        
        # Start CPU burning threads
        burn_threads = []
        for _ in range( threads ):
            t = threading.Thread( target=cpu_burn )
            t.start()
            burn_threads.append( t )
        
        # Run for specified duration
        time.sleep( duration )
        stop_event.set()
        
        # Wait for threads to finish
        for t in burn_threads:
            t.join( timeout=2 )
        
        return {
            'status': 'completed',
            'type': 'cpu_spike',
            'threads_used': threads,
            'duration': duration
        }
    
    # Simulate memory leak
    def _SimMemory( self, duration: int, intensity: str ) -> Dict:
        print( f"Simulating memory leak for {duration} seconds..." )
        
        # Determine allocation rate based on intensity
        if intensity == 'low':
            chunk_size = 1024 * 1024  # 1MB
            delay = 0.5
        elif intensity == 'medium':
            chunk_size = 5 * 1024 * 1024  # 5MB
            delay = 0.3
        else:  # high
            chunk_size = 10 * 1024 * 1024  # 10MB
            delay = 0.1
        
        memory_hog = []
        start_time = time.time()
        allocated = 0
        
        try:
            while time.time() - start_time < duration:
                # Allocate memory chunk
                chunk = bytearray( chunk_size )
                memory_hog.append( chunk )
                allocated += chunk_size
                
                print( f"Allocated: {allocated // (1024*1024 )} MB", end='\r' )
                time.sleep( delay )
            
            # Hold memory for a bit then release
            time.sleep( 2 )
            
        except MemoryError:
            print( "\nMemory exhausted!" )
        finally:
            # Clean up memory
            memory_hog.clear()
            print( f"\nMemory released" )
        
        return {
            'status': 'completed',
            'type': 'memory_leak',
            'max_allocated_mb': allocated // (1024*1024),
            'duration': duration
        }
    
    # Simulate disk space exhaustion
    def _SimDisk( self, duration: int, intensity: str ) -> Dict:
        print( f"Simulating disk fill for {duration} seconds..." )
        
        # Determine file size based on intensity
        if intensity == 'low':
            file_size = 10 * 1024 * 1024  # 10MB
        elif intensity == 'medium':
            file_size = 50 * 1024 * 1024  # 50MB
        else:  # high
            file_size = 100 * 1024 * 1024  # 100MB
        
        temp_dir = tempfile.gettempdir()
        created_files = []
        total_written = 0
        
        try:
            start_time = time.time()
            
            while time.time() - start_time < duration:
                # Create temporary file
                temp_file = tempfile.NamedTemporaryFile( 
                    dir=temp_dir, 
                    delete=False,
                    prefix='incident_sim_'
                )
                
                # Write data to file
                data = b'X' * min( file_size, 1024*1024 )  # Write in 1MB chunks
                bytes_written = 0
                
                while bytes_written < file_size:
                    chunk_size = min( 1024*1024, file_size - bytes_written )
                    temp_file.write( data[:chunk_size] )
                    bytes_written += chunk_size
                    total_written += chunk_size
                
                temp_file.close()
                created_files.append( temp_file.name )
                self.temp_files.append( temp_file.name )
                
                print( f"Written: {total_written // (1024*1024 )} MB", end='\r' )
                time.sleep( 0.1 )
            
        except Exception as e:
            print( f"\nError writing files: {e}" )
        finally:
            # Clean up files
            print( f"\nCleaning up {len( created_files )} temporary files..." )
            for file_path in created_files:
                try:
                    os.remove( file_path )
                    if file_path in self.temp_files:
                        self.temp_files.remove( file_path )
                except:
                    pass
        
        return {
            'status': 'completed',
            'type': 'disk_fill',
            'files_created': len( created_files ),
            'total_mb_written': total_written // ( 1024*1024 ),
            'duration': duration
        }
    
    # Simulate DNS failure
    def _SimDNS( self, duration: int, intensity: str ) -> Dict:
        print( f"Simulating DNS issues for {duration} seconds..." )
        
        # Determine query rate based on intensity
        if intensity == 'low':
            queries_per_sec = 5
        elif intensity == 'medium':
            queries_per_sec = 15
        else:  # high
            queries_per_sec = 30
        
        failed_queries = 0
        successful_queries = 0
        
        # List of domains to query
        test_domains = [
            'google.com', 'facebook.com', 'amazon.com', 'microsoft.com',
            'apple.com', 'netflix.com', 'github.com', 'stackoverflow.com'
        ]
        
        start_time = time.time()
        
        while time.time() - start_time < duration:
            for _ in range( queries_per_sec ):
                domain = random.choice( test_domains )
                try:
                    # Attempt DNS resolution
                    socket.gethostbyname( domain )
                    successful_queries += 1
                except socket.gaierror:
                    failed_queries += 1
                except Exception:
                    failed_queries += 1
            
            print( f"Queries - Success: {successful_queries}, Failed: {failed_queries}", end='\r' )
            time.sleep( 1 )
        
        return {
            'status': 'completed',
            'type': 'dns_failure',
            'successful_queries': successful_queries,
            'failed_queries': failed_queries,
            'duration': duration
        }
    
    # Simulate port exhaustion
    def _SimPorts( self, duration: int, intensity: str ) -> Dict:
        print( f"Simulating port exhaustion for {duration} seconds..." )
        
        # Determine connection count based on intensity
        if intensity == 'low':
            max_connections = 100
        elif intensity == 'medium':
            max_connections = 500
        else:  # high
            max_connections = 1000
        
        connections = []
        opened = 0
        
        try:
            start_time = time.time()
            
            while time.time() - start_time < duration and opened < max_connections:
                try:
                    # Create socket connection
                    sock = socket.socket( socket.AF_INET, socket.SOCK_STREAM )
                    sock.settimeout( 1 )
                    
                    # Try to connect to various ports on localhost
                    port = random.randint( 8000, 9000 )
                    result = sock.connect_ex( ( '127.0.0.1', port ) )
                    
                    connections.append( sock )
                    opened += 1
                    
                    if opened % 50 == 0:
                        print( f"Opened connections: {opened}", end='\r' )
                    
                    time.sleep( 0.01 )
                    
                except Exception:
                    continue
            
        finally:
            # Clean up connections
            print( f"\nClosing {len( connections )} connections..." )
            for sock in connections:
                try:
                    sock.close()
                except:
                    pass
        
        return {
            'status': 'completed',
            'type': 'port_exhaust',
            'connections_opened': opened,
            'max_attempted': max_connections,
            'duration': duration
        }
    
    # Simulate I/O storm
    def _SimIO( self, duration: int, intensity: str ) -> Dict:
        print( f"Simulating I/O storm for {duration} seconds..." )
        
        # Determine I/O intensity
        if intensity == 'low':
            threads = 2
            file_size = 1024 * 1024  # 1MB
        elif intensity == 'medium':
            threads = 4
            file_size = 5 * 1024 * 1024  # 5MB
        else:  # high
            threads = 8
            file_size = 10 * 1024 * 1024  # 10MB
        
        stop_event = threading.Event()
        operations = {'reads': 0, 'writes': 0}
        lock = threading.Lock()
        
        def io_worker():
            temp_file = tempfile.NamedTemporaryFile( delete=False )
            data = b'A' * file_size
            
            try:
                while not stop_event.is_set():
                    # Write operation
                    temp_file.write( data )
                    temp_file.flush()
                    os.fsync( temp_file.fileno() )
                    
                    with lock:
                        operations['writes'] += 1
                    
                    # Read operation
                    temp_file.seek( 0 )
                    temp_file.read()
                    
                    with lock:
                        operations['reads'] += 1
                    
                    if operations['reads'] % 10 == 0:
                        print( f"I/O Ops - Reads: {operations['reads']}, Writes: {operations['writes']}", end='\r' )
                    
                    time.sleep( 0.01 )
            finally:
                temp_file.close()
                try:
                    os.unlink( temp_file.name )
                except:
                    pass
        
        # Start I/O worker threads
        io_threads = []
        for _ in range( threads ):
            t = threading.Thread( target=io_worker )
            t.start()
            io_threads.append( t )
        
        # Run for specified duration
        time.sleep( duration )
        stop_event.set()
        
        # Wait for threads to finish
        for t in io_threads:
            t.join( timeout=2 )
        
        return {
            'status': 'completed',
            'type': 'io_storm',
            'total_reads': operations['reads'],
            'total_writes': operations['writes'],
            'threads_used': threads,
            'duration': duration
        }
    
    # Simulate network latency
    def _SimNetwork( self, duration: int, intensity: str ) -> Dict:
        print( f"Simulating network latency for {duration} seconds..." )
        
        # Determine ping frequency based on intensity
        if intensity == 'low':
            ping_interval = 2.0
        elif intensity == 'medium':
            ping_interval = 1.0
        else:  # high
            ping_interval = 0.5
        
        targets = ['8.8.8.8', '1.1.1.1', '208.67.222.222']
        ping_results = []
        
        start_time = time.time()
        
        while time.time() - start_time < duration:
            for target in targets:
                try:
                    # Ping target
                    if os.name == 'nt':  # Windows
                        result = subprocess.run( 
                            ['ping', '-n', '1', target],
                            capture_output=True,
                            text=True,
                            timeout=5
                        )
                    else:  # Unix/Linux
                        result = subprocess.run( 
                            ['ping', '-c', '1', target],
                            capture_output=True,
                            text=True,
                            timeout=5
                        )
                    
                    success = result.returncode == 0
                    ping_results.append( {
                        'target': target,
                        'success': success,
                        'timestamp': datetime.now().isoformat()
                    } )
                    
                except subprocess.TimeoutExpired:
                    ping_results.append( {
                        'target': target,
                        'success': False,
                        'error': 'timeout',
                        'timestamp': datetime.now().isoformat()
                    } )
                except Exception as e:
                    ping_results.append( {
                        'target': target,
                        'success': False,
                        'error': str( e ),
                        'timestamp': datetime.now().isoformat()
                    } )
            
            successful = sum( 1 for r in ping_results if r.get( 'success', False ) )
            total = len( ping_results )
            print( f"Network tests - Success: {successful}/{total}", end='\r' )
            
            time.sleep( ping_interval )
        
        successful_pings = sum( 1 for r in ping_results if r.get('success', False ) )
        
        return {
            'status': 'completed',
            'type': 'network_lag',
            'total_pings': len( ping_results ),
            'successful_pings': successful_pings,
            'packet_loss_percent': round( ( 1 - successful_pings/len( ping_results ) ) * 100, 2 ) if ping_results else 0,
            'duration': duration
        }
    
    # Simulate process fork bomb (limited and safe)
    def _SimProcesses( self, duration: int, intensity: str ) -> Dict:
        print( f"Simulating process spawn for {duration} seconds..." )
        print( "WARNING: This creates many processes - use with caution!" )
        
        # Determine process count based on intensity (keep it safe)
        if intensity == 'low':
            max_processes = 10
        elif intensity == 'medium':
            max_processes = 25
        else:  # high
            max_processes = 50
        
        processes = []
        created = 0
        
        try:
            start_time = time.time()
            
            while time.time() - start_time < duration and created < max_processes:
                try:
                    # Create a simple process that sleeps
                    if os.name == 'nt':  # Windows
                        proc = subprocess.Popen( ['timeout', '60'], 
                                              stdout=subprocess.DEVNULL, 
                                              stderr=subprocess.DEVNULL )
                    else:  # Unix/Linux
                        proc = subprocess.Popen( ['sleep', '60'], 
                                              stdout=subprocess.DEVNULL, 
                                              stderr=subprocess.DEVNULL )
                    
                    processes.append( proc )
                    created += 1
                    self.temp_processes.append( proc )
                    
                    print( f"Processes created: {created}", end='\r' )
                    time.sleep( 0.1 )
                    
                except Exception as e:
                    print( f"Error creating process: {e}" )
                    break
            
        finally:
            # Clean up processes
            print( f"\nTerminating {len( processes )} processes..." )
            for proc in processes:
                try:
                    proc.terminate()
                    proc.wait( timeout=2 )
                    if proc in self.temp_processes:
                        self.temp_processes.remove( proc )
                except:
                    try:
                        proc.kill()
                    except:
                        pass
        
        return {
            'status': 'completed',
            'type': 'process_bomb',
            'processes_created': created,
            'max_attempted': max_processes,
            'duration': duration
        }
    
    # Stop all active simulations
    def StopAll( self ) -> Dict:
        print( "Stopping all active simulations..." )
        
        stopped = 0
        
        # Clean up temporary files
        for file_path in self.temp_files:
            try:
                os.remove( file_path )
                stopped += 1
            except:
                pass
        self.temp_files.clear()
        
        # Terminate temporary processes
        for proc in self.temp_processes:
            try:
                proc.terminate()
                proc.wait( timeout=2 )
                stopped += 1
            except:
                try:
                    proc.kill()
                    stopped += 1
                except:
                    pass
        self.temp_processes.clear()
        
        # Clear active simulations
        self.active_sims.clear()
        
        return {
            'status': 'completed',
            'items_cleaned': stopped
        }
    
    # Show available scenarios
    def ShowScenarios( self ):
        print( f"\n{'='*60}" )
        print( f"AVAILABLE INCIDENT SCENARIOS" )
        print( f"{'='*60}" )
        
        for key, scenario in self.scenarios.items():
            print( f"\n{key.upper( )}" )
            print( f"  Name: {scenario['name']}" )
            print( f"  Description: {scenario['description']}" )
            print( f"  Severity: {scenario['severity']}" )
            print( f"  Duration: {scenario['duration']}" )
    
    # Show simulation history
    def ShowHistory( self ):
        if not self.sim_history:
            print( "No simulations have been run yet." )
            return
        
        print( f"\n{'='*60}" )
        print( f"SIMULATION HISTORY" )
        print( f"{'='*60}" )
        
        for i, sim in enumerate( self.sim_history[-10:], 1 ):  # Show last 10
            print( f"\n{i}. {sim['scenario'].upper( )}")
            print( f"   Start: {sim['start_time']}" )
            print( f"   Duration: {sim['duration']} seconds" )
            print( f"   Intensity: {sim['intensity']}" )
            print( f"   Status: {sim['result'].get( 'status', 'unknown' )}" )
    
    # Export simulation history
    def Export( self, filename: str ):
        try:
            with open( filename, 'w' ) as f:
                json.dump( self.sim_history, f, indent=2, default=str )
            print( f"Simulation history exported to: {filename}" )
        except Exception as e:
            print( f"Export failed: {e}" )
    
    # Show help information
    def ShowHelp( self ):
        print( f"\n{'='*60}" )
        print( f"INCIDENT SIMULATOR - HELP" )
        print( f"{'='*60}" )
        print( f"Commands:" )
        print( f"  start <scenario> [duration] [intensity]  - Start incident simulation" )
        print( f"  scenarios                               - List available scenarios" )
        print( f"  history                                 - Show simulation history" )
        print( f"  stop                                    - Stop all simulations" )
        print( f"  export <filename>                       - Export history to JSON" )
        print( f"  help                                    - Show this help" )
        print( f"  quit                                    - Exit program" )
        print( f"\nScenarios:" )
        for key in self.scenarios.keys():
            print( f"  - {key}" )
        print( f"\nIntensity levels: low, medium, high" )
        print( f"\nExamples:" )
        print( f"  start cpu_spike 60 high" )
        print( f"  start memory_leak 120 medium" )
        print( f"  start disk_fill 300 low" )
        print( f"\nWARNING: Use responsibly! These simulations can impact system performance." )

# Print application banner
def ShowBanner():
    banner = """
    ==============================================================
                        Incident Simulator                       
                       Author: Andrew Piggot                
    ==============================================================
    """
    print( banner )

# Main application function
def main():
    ShowBanner()
    simulator = IncidentTool()
    
    print( "Welcome to the Incident Simulator!" )
    print( "Type 'help' for commands or 'scenarios' to see available simulations" )
    print( "WARNING: Use in controlled environments only!\n" )
    
    try:
        while True:
            user_input = input( "incident-sim> " ).strip()
            
            if not user_input:
                continue
            
            parts = user_input.split()
            command = parts[0].lower()
            
            if command in ['quit', 'exit', 'q']:
                # Clean up before exit
                simulator.StopAll()
                print( "Goodbye! Stay prepared!" )
                break
            
            elif command == 'help':
                simulator.ShowHelp()
            
            elif command == 'scenarios':
                simulator.ShowScenarios()
            
            elif command == 'history':
                simulator.ShowHistory()
            
            elif command == 'stop':
                result = simulator.StopAll()
                print( f"Cleaned up {result['items_cleaned']} items" )
            
            elif command == 'start':
                if len( parts ) < 2:
                    print( "Usage: start <scenario> [duration] [intensity]" )
                    continue
                
                scenario = parts[1]
                duration = int( parts[2] ) if len( parts ) > 2 else None
                intensity = parts[3] if len( parts ) > 3 else 'medium'
                
                if intensity not in ['low', 'medium', 'high']:
                    print( "Intensity must be: low, medium, or high" )
                    continue
                
                print( f"\nStarting {scenario} simulation..." )
                result = simulator.StartSim( scenario, duration, intensity )
                
                if 'error' in result:
                    print( f"Error: {result['error']}" )
                else:
                    print( f"Simulation result: {result}" )
            
            elif command == 'export':
                if len( parts ) > 1:
                    filename = parts[1]
                    simulator.Export( filename )
                else:
                    print( "Usage: export <filename>" )
            
            else:
                print( f"Unknown command: {command}" )
                print( "Type 'help' for available commands" )
    
    except KeyboardInterrupt:
        print( "\n\nEmergency stop - cleaning up..." )
        simulator.StopAll()
        print( "Goodbye!" )
    except Exception as e:
        print( f"\nUnexpected error: {e}" )
        simulator.StopAll()

if __name__ == "__main__":
    main()
