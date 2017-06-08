#!/usr/bin/python3
# Author: Alex Madon, Alfresco
# First version: November 21013
# this is a AJPv13 client written in pure Python (no dependencies)
# use the -h option to get help



import socket
import binascii
import argparse
import urllib.parse
import sys

"""
Packet Format (Server->Container)
Byte 	        0 	1 	2 	3 	4...(n+3)
Contents 	0x12 	0x34 	Data Length (n) 	Data
"""


# loglevel='DEBUG'

def print_debug(*args):
    # if loglevel=='DEBUG' or loglevel=='DEBUG':
    # print('DEBUG',*args,file=sys.stderr)
    pass

def print_info(*args):
    # if loglevel=='INFO':
    # print('INFO',*args,file=sys.stderr)
    pass

def print_head(*args):
    print(*args,file=sys.stderr)

def print_data(*args):
    print(*args) # used to print to stdout

def S(message_bytes):
    # an AJP string
    # the length of the string on two bytes + string + plus two null bytes
    message_len_int=len(message_bytes)
    message_len_bytes=message_len_int.to_bytes(2,'big') # convert to a two bytes

    end_hex=b'00'
    end_bytes=binascii.a2b_hex(end_hex)

    return message_len_bytes+message_bytes+end_bytes

def known_headers(headername):
    # some headers have a special code, see specs
    known={}
    known[b'accept']=b'A001' # 	SC_REQ_ACCEPT
    known[b'accept-charset']=b'A002' #  	SC_REQ_ACCEPT_CHARSET
    known[b'accept-encoding']=b'A003' #  	SC_REQ_ACCEPT_ENCODING
    known[b'accept-language']=b'A004' #  	SC_REQ_ACCEPT_LANGUAGE
    known[b'authorization']=b'A005' #  	SC_REQ_AUTHORIZATION
    known[b'connection']=b'A006' #  	SC_REQ_CONNECTION
    known[b'content-type']=b'A007' #  	SC_REQ_CONTENT_TYPE
    known[b'content-length']=b'A008' #  	SC_REQ_CONTENT_LENGTH
    known[b'cookie']=b'A009' #  	SC_REQ_COOKIE
    known[b'cookie2']=b'A00A ' # 	SC_REQ_COOKIE2
    known[b'host']=b'A00B' #  	SC_REQ_HOST
    known[b'pragma']=b'A00C' #  	SC_REQ_PRAGMA
    known[b'referer']=b'A00D' #  	SC_REQ_REFERER
    known[b'user-agent']=b'A00E' #  	SC_REQ_USER_AGENT
    code=known.get(headername,b'')
    return code

def known_attributes(attributename):
    known={}
    known[b'remote_user']=b'03'	
    known[b'auth_type']=b'04' 	
    known[b'query_string']=b'05' 	
    known[b'jvm_route']=b'06' 	
    known[b'ssl_cert']=b'07' 	
    known[b'ssl_cipher']=b'08' 	
    known[b'ssl_session']=b'09' 	
    known[b'req_attribute']=b'0A' 	# Name (the name of the attribut follows)
    known[b'ssl_key_size']=b'0B'
    code=known.get(attributename,b'')
    return code

def known_methods(method):
    known={}
    known['OPTIONS']=1
    known['GET']=2
    known['HEAD']=3
    known['POST']=4
    known['PROPFIND']=8
    code=known.get(method,2)
    return code

def message_forward_request(headers,requesturl,passurl,remote_user,method):
    print_head('>',method,requesturl,'(via',passurl,')')
    if remote_user:
        print_head('>','remote_user:',remote_user.decode('utf8'))
    # parse the request to be proxied
    req_ob=urllib.parse.urlparse(requesturl)


    header_hex=b'1234'
    header_bytes=binascii.a2b_hex(header_hex)

    # JK_AJP13_FORWARD_REQUEST
    prefix_code_int=2
    prefix_code_bytes=prefix_code_int.to_bytes(1,'big') # convert to a one byte number
    prefix_code_hex=binascii.b2a_hex(prefix_code_bytes)
    print_debug('code',prefix_code_int,prefix_code_bytes,prefix_code_hex) # 0x02 = JK_AJP13_FORWARD_REQUEST

    # method GET code 2 (The HTTP method, encoded as a single byte)
    method_int=known_methods(method) # 2
    method_bytes=method_int.to_bytes(1,'big') # convert to a one byte number
    method_hex=binascii.b2a_hex(method_bytes)
    print_debug('method',method_int,method_bytes,method_hex) # 0x02 = JK_AJP13_FORWARD_REQUEST

    protocol_bytes=b'HTTP/1.1'
    protocol_hex=binascii.b2a_hex(protocol_bytes)
    print_debug('protocol',protocol_bytes,protocol_hex)


    # req_uri_bytes=b'/alfresco/'
    # req_uri_bytes=b'/alfresco/faces/jsp/dashboards/container.jsp'
    req_uri_bytes=req_ob.path.encode('utf8')
    req_uri_hex=binascii.b2a_hex(req_uri_bytes)
    print_debug('uri',req_uri_bytes,req_uri_hex)


    remote_addr_bytes=b'127.0.0.1'
    remote_addr_hex=binascii.b2a_hex(remote_addr_bytes)

    remote_host_bytes=b'localhost'
    remote_host_hex=binascii.b2a_hex(remote_host_bytes)

    # server_name_bytes=b'localhost'
    server_name_bytes=req_ob.hostname.encode('utf8')
    server_name_hex=binascii.b2a_hex(server_name_bytes)

    # port 
    server_port_int=req_ob.port 
    if not(server_port_int):
        server_port_int=80 # 80
    server_port_bytes=server_port_int.to_bytes(2,'big') # convert to a two bytes
    server_port_hex=binascii.b2a_hex(server_port_bytes)

    # SSL flag
    if req_ob.scheme=='https':
        is_ssl_boolean=1
    else:
        is_ssl_boolean=0
    is_ssl_bytes=is_ssl_boolean.to_bytes(1,'big') # convert to a one byte
    is_ssl_hex=binascii.b2a_hex(is_ssl_bytes)
    print_debug('is_ssl_boolean',is_ssl_boolean)

    headers.append((b'host',b'localhost'))

    num_headers_int=len(headers)
    num_headers_bytes=num_headers_int.to_bytes(2,'big') # convert to a two bytes
    num_headers_hex=binascii.b2a_hex(num_headers_bytes)

    headers_ajp=[]

    for (header_name, header_value) in headers:
        code=known_headers(header_name)
        if code!=b'':
            header_code_hex=code
            header_code_bytes=binascii.a2b_hex(header_code_hex)
            print_debug('header',header_code_hex,header_code_bytes)
            headers_ajp.append(header_code_bytes)
            headers_ajp.append(S(header_value))
        else:
            print_debug('unkown header', (header_name, header_value))
            headers_ajp.append(S(header_name))
            headers_ajp.append(S(header_value))
 

    headers_ajp_bytes=b''.join(headers_ajp)
    print_debug('headers_ajp_bytes',headers_ajp_bytes)


    attributes=[]
    if remote_user:
        attributes.append((b'remote_user',remote_user))

    attributes_ajp=[]

    for (attribute_name, attribute_value) in attributes:
        code=known_attributes(attribute_name)
        if code!=b'':
            # if attribute_name==b'host':
            # attribute_code_hex=b'A00B'
            attribute_code_hex=code
            attribute_code_bytes=binascii.a2b_hex(attribute_code_hex)
            print_debug('attribute',attribute_code_hex,attribute_code_bytes)
            attributes_ajp.append(attribute_code_bytes)
            attributes_ajp.append(S(attribute_value))
        # if attribute_name==b'authorization':
    attributes_ajp_bytes=b''.join(attributes_ajp)
    print_debug('attributes_ajp_bytes',attributes_ajp_bytes)


    request_terminator_hex=b'FF'
    request_terminator_bytes=binascii.a2b_hex(request_terminator_hex)

    message=[]
    message.append(prefix_code_bytes)
    message.append(method_bytes)
    message.append(S(protocol_bytes))
    message.append(S(req_uri_bytes))
    message.append(S(remote_addr_bytes))
    message.append(S(remote_host_bytes))
    message.append(S(server_name_bytes))
    message.append(server_port_bytes)
    message.append(is_ssl_bytes)
    message.append(num_headers_bytes)
    message.append(headers_ajp_bytes)
    message.append(attributes_ajp_bytes)
    message.append(request_terminator_bytes)
    message_bytes=b''.join(message)

    # we use S() 

    send_bytes=header_bytes+S(message_bytes)
    print_debug(send_bytes)
    print_debug(binascii.b2a_hex(send_bytes))
    return send_bytes

def message_cping():
    header=binascii.a2b_hex(b'1234') # ajp header
    
    print_debug('header bytes',header)
    print_debug('header hex',binascii.b2a_hex(header))


    code=10 # ajp cping request
    packetcode=code.to_bytes(1,'big') # convert to a one byte number
    
    packetrequest =packetcode # this is a simple ping, so request == code
    print_debug('packetrequest bytes',packetrequest)
    print_debug('packetrequest hex',binascii.b2a_hex(packetrequest))

    requestlen=len(packetrequest)
    packetrequestlen=requestlen.to_bytes(2,'big') # convert to a two bytes
    


    mess=[]
    mess.append(header)
    mess.append(packetrequestlen)
    mess.append(packetrequest)
    
    message=b''.join(mess)
    
    
    print_debug('MESSAGE=',message)
    print_debug('message hex',binascii.b2a_hex(message))
    return message

# reply should be:
# data b'AB\x00\x01\t'
# dHex b'41|42|0001|09|'
# 9 	CPong Reply 	The reply to a CPing request



# =========================================================================
#
#  AJP13 Response
#
# =========================================================================

def get_common_response_header(second_byte):
    # from https://tomcat.apache.org/connectors-doc/ajp/ajpv13a.html
    common_response_headers={
        b'\x01': b'Content-Type',
        b'\x02': b'Content-Language',
        b'\x03': b'Content-Length',
        b'\x04': b'Date',
        b'\x05': b'Last-Modified',
        b'\x06': b'Location',
        b'\x07': b'Set-Cookie',
        b'\x08': b'Set-Cookie2',
        b'\x09': b'Servlet-Engine',
        b'\x0a': b'Status',
        b'\x0b': b'WWW-Authenticate',

        }
    return common_response_headers[second_byte]

def parse_response_end(s):
    print_debug('parsing END')
    code_reuse_bytes=s.recv(1)
    code_reuse_int=int.from_bytes(code_reuse_bytes,byteorder='big')
    print_debug('code_reuse',code_reuse_bytes,code_reuse_int)
    print_debug("that's the end, I am closing......")
    s.close()
    quit()

def parse_response_send_body_chunk(s):
    print_debug('parsing BODY CHUNK')
    chunk_len_bytes=s.recv(2)
    chunk_len_int=int.from_bytes(chunk_len_bytes,byteorder='big')
    print_debug('chunk_len',chunk_len_bytes,chunk_len_int)

    chunk=s.recv(chunk_len_int)
    print_debug('chunk',chunk)
    print(chunk.decode('utf8'),end='')
    # consume the 0x00 terminator
    s.recv(1)



def parse_response_headers(s):
    print_debug('parsing RESPONSE HEADERS')
    rstatus_bytes=s.recv(2)
    rstatus_int=int.from_bytes(rstatus_bytes,byteorder='big')
    print_debug('rstatus',rstatus_bytes,rstatus_int)

    rmsg_len_bytes=s.recv(2)
    rmsg_len_int=int.from_bytes(rmsg_len_bytes,byteorder='big')
    print_debug('rmsg_len',rmsg_len_int)

    rmsg_bytes=s.recv(rmsg_len_int)
    print_debug('rmsg_bytes',rmsg_bytes)

    print_head('<',rstatus_int,rmsg_bytes.decode('utf8'))
    # consume the 0x00 terminator
    s.recv(1)

    headers_nb_bytes=s.recv(2)
    headers_nb_int=int.from_bytes(headers_nb_bytes,byteorder='big')
    print_debug('headers_nb',headers_nb_bytes,headers_nb_int)

    print_info(rstatus_int,rmsg_bytes,)
    print_debug('--- doing response headers ----')
    for i in range(0,headers_nb_int):
        # header name: two cases
        first_byte=s.recv(1)
        second_byte=s.recv(1)
        print_debug('first_byte',first_byte)
        print_debug('second_byte',second_byte)

        if first_byte==b'\xa0':
            print_debug('we have a common header',second_byte)
            header_bytes=get_common_response_header(second_byte)
            print_debug('header_bytes',header_bytes)
        else:
            print_debug('we have an uncommon header, process a string')


            # header_len_bytes=s.recv(2)
            header_len_bytes=first_byte+second_byte
            print_debug('header_len_bytes',i,header_len_bytes)
            header_len_int=int.from_bytes(header_len_bytes,byteorder='big')
            print_debug('header',i,'length',header_len_int)
            
            
            
            header_bytes=s.recv(header_len_int)
            print_debug('header',i,header_bytes)

            # consume the 0x00 terminator
            s.recv(1)



        

        # get the value of the header as a string: 2bytes give length + value + 0x00 terminator
        headerv_len_bytes=s.recv(2)
        headerv_len_int=int.from_bytes(headerv_len_bytes,byteorder='big')
        print_debug('headerv',i,'length',headerv_len_int)
        



        headerv_bytes=s.recv(headerv_len_int)
        print_debug('headerv',i,headerv_bytes)
        
        # print_head('<',header_bytes.decode('utf8'),headerv_bytes.decode('utf8'))
        print_head('<',header_bytes,headerv_bytes)
        # consume the 0x00 terminator
        s.recv(1)

        print_info(header_bytes,headerv_bytes)



def parse_response(s):
    print_debug('parsing response')

    magic=s.recv(2) # first two bytes are the 'magic'
    print_debug('magic',magic,binascii.b2a_hex(magic))
    # next two bytes are the length

    len_bytes=s.recv(2)
    len_int=int.from_bytes(len_bytes,byteorder='big')
    print_debug('len_bytes',len_bytes,len_int)

    code_bytes=s.recv(1)
    code_int=int.from_bytes(code_bytes,byteorder='big')
    print_debug('code',code_bytes,code_int)
    
    if code_int==4:
        parse_response_headers(s)
    if code_int==3:
        parse_response_send_body_chunk(s)
    if code_int==5:
        parse_response_end(s)

    parse_response(s)
    # rest=s.recv(len_int)
    # print_debug('rest',rest)


# =========================================================================
#
#  Socket Utilities
#
# =========================================================================




def getLine(afile):
    """ 
    Reads the response of the server, byte per byte,
    and returns a line of the server response
    The line returned is in byte format, not in 
    any encoded form.
    
    In the end, the socket points to the start of the next line
    
    @param line: Socket communicating with the redis server
    @return: A line of bytes
    """
    yy=atpic.log.setname(xx,'getLine')
    line = b""
    while True:
        next_byte = afile.read(1)  # read a byte
        atpic.log.debug(yy,'read next_byte',next_byte)
        if next_byte==b'':
            atpic.log.debug(yy,'got empty bytes, needs to QUIT!')
            # quit()
            return b''
        # print_debug('next_byte',next_byte)
        if next_byte == b"\n":    # if it's end of line, break
            # print_debug('got newline, breaking')
            break
        else:           
            line += next_byte         # otherwise, stick it with the rest
    return line


def transform_headers(headers):
    newheaders=[]
    for header in headers:
        hsplit=header.split(':')
        hname=hsplit[0]
        hvalue=':'.join(hsplit[1:])
        newheaders.append((hname.lower().encode('utf8'),hvalue.encode('utf8')))
    print_debug(newheaders)
    return newheaders

def send_and_read(headers,requesturl,passurl,remote_user,method):
    print_debug("Hi")
    # message=message_cping()
    message=message_forward_request(headers,requesturl,passurl,remote_user,method)
    passob=urllib.parse.urlparse(passurl)
    TCP_IP = passob.hostname
    TCP_PORT = passob.port


    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((TCP_IP, TCP_PORT))
    s.send(message)


    parse_response(s)


if __name__ == "__main__":
    # parse command line arguments
    parser = argparse.ArgumentParser(description='A python AJP client',epilog="""The AJPv13 protocol is documented at: 
http://tomcat.apache.org/connectors-doc-archive/jk2/common/AJPv13.html""")   
    parser.add_argument('-H', '--header', help='adds a header', action='append')
    parser.add_argument('-r', '--remote_user', help='Sets the remote_user CGI variable')
    parser.add_argument('-X', help='Sets the method (default: %(default)s).',default='GET',choices=['GET','POST','HEAD','OPTIONS','PROPFIND'])
    parser.add_argument('-l', '--log_level', help='Sets the log level. Logs are sent to STDERR.',choices=['INFO','DEBUG'])
    parser.add_argument('-d', '--data', nargs=1, help='The data to POST')
    parser.add_argument('requesturl', nargs=1, help='The request to the proxy front end, e.g. http://localhost/alfresco/faces/jsp/dashboards/container.jsp')
    parser.add_argument('passurl', nargs='?', default='ajp://localhost:8009/alfresco', help='The proxy pass url (default: %(default)s)')
    args = parser.parse_args()
 

    headers=args.header
    passurl=args.passurl
    remote_user=args.remote_user
    requesturl=args.requesturl[0]
    if headers==None:
        headers=[]
    headers=transform_headers(headers)
    if remote_user:
        remote_user=remote_user.encode('utf8')
    loglevel=args.log_level
    method=args.X
    print_debug(headers,requesturl,passurl,remote_user,loglevel,method)
    print_debug(args)
    # quit()
    # quit()
    send_and_read(headers,requesturl,passurl,remote_user,method)
    # admin:admin YWRtaW46YWRtaW4=
    # -H authorization:YWRtaW46YWRtaW4= 
