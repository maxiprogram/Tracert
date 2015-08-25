#include <windows.h>
#include <iphlpapi.h>
#include <icmpapi.h>
#include <stdio.h>
#include <commctrl.h>
#include "resource.h"

#pragma comment(lib,"comctl32.lib")
#pragma comment(lib,"wsock32.lib")
#pragma comment(lib,"icm32.lib")
#pragma comment(lib,"iphlpapi.Lib")

LRESULT CALLBACK Func(HWND wnd,UINT msg,WPARAM wp,LPARAM lp);
unsigned long __stdcall onthread(void* param);
void Add_to_list_box(char* str,HWND wnd);
unsigned int convert(unsigned int ip);
int Tracert(char* str_ip,unsigned int max_ttl,unsigned int interval,HWND wnd);

struct data_param
{
char* ip;
unsigned int max_ttl;
unsigned int interval;
HWND wnd;
};

int __stdcall WinMain(HINSTANCE h,HINSTANCE hi,LPSTR s,int cmd)
{
	INITCOMMONCONTROLSEX icc;
	icc.dwSize=sizeof(icc);
	icc.dwICC=ICC_STANDARD_CLASSES;
	InitCommonControlsEx(&icc);
	HWND wnd=NULL;
	wnd=CreateDialogA(h,MAKEINTRESOURCEA(MAIN),NULL,(DLGPROC)Func);
	if (wnd==NULL)
	{
		MessageBoxA(NULL,"Error CreateWindow!","Error!",0);
		return 1;	
	}
	ShowWindow(wnd,SW_SHOW);
	MSG msg;
	while(GetMessage(&msg,NULL,0,0))
	{
		if (!IsDialogMessage(wnd,&msg))
		{
			TranslateMessage(&msg);
			DispatchMessage(&msg);
		}
	}

	return 0;
}

LRESULT CALLBACK Func(HWND wnd,UINT msg,WPARAM wp,LPARAM lp)
{
	switch(msg)
	{
	case WM_INITDIALOG:
		{
			DWORD llp=MAKEIPADDRESS(127,0,0,1);
			SendDlgItemMessage(wnd,IDC_LIST1,IPM_SETADDRESS,0,(LPARAM)llp);
			SendDlgItemMessage(wnd,IDC_EDIT1,WM_SETTEXT,0,(LPARAM)"30");
			SendDlgItemMessage(wnd,IDC_EDIT2,WM_SETTEXT,0,(LPARAM)"3000");
			return 1;
		}

	case WM_COMMAND:
		{
			switch(LOWORD(wp))
			{
			case IDC_OK:
				{
					data_param* param=new data_param();
					char str[20];
					SendDlgItemMessage(wnd,IDC_EDIT1,WM_GETTEXT,20,(LPARAM)str);
					param->max_ttl=atoi(str);
					//unsigned int max_ttl=atoi(str);
					SendDlgItemMessage(wnd,IDC_EDIT2,WM_GETTEXT,20,(LPARAM)str);
					param->interval=atoi(str);
					//unsigned int iterval=atoi(str);
					unsigned long ip;
					SendDlgItemMessage(wnd,IDC_IPADDRESS1,IPM_GETADDRESS,NULL,(LPARAM)(LPDWORD)&ip);
					ip=convert(ip);
					SOCKADDR_IN ad;
					ad.sin_addr.s_addr=ip;
					char b[255];
					param->ip=&b[0];
					param->ip=inet_ntoa(ad.sin_addr); 
					param->wnd=wnd;
					HANDLE ha=CreateThread(NULL,0,onthread,(LPVOID)param,0,NULL);
					if (ha==NULL)
					{
						MessageBoxA(wnd,"Ошибка создания потока!","Ошибка",0);
						return 1;
					}
					//Tracert(param->ip,param->max_ttl,param->interval,param->wnd);
					//delete param;
					return 1;
				}
			case IDC_CLEAR:
				{
					SendDlgItemMessage(wnd,IDC_LIST1,LB_RESETCONTENT,0,0);
					return 1;
				}
			default:return 0;
			}
		
		}
	case WM_DESTROY:
		{
			PostQuitMessage(0);
			return 1;
		}
	
	case WM_CLOSE:
		{
			DestroyWindow(wnd);
			return 1;
		}
	default:return 0;
	}
}

void Add_to_list_box(char* str,HWND wnd)
{
	SendDlgItemMessage(wnd,IDC_LIST1,LB_ADDSTRING,0,(LPARAM)str);
}

unsigned long __stdcall onthread(void* param)
{
	data_param* data=(data_param*)param;
	Tracert(data->ip,data->max_ttl,data->interval,data->wnd);
	delete data;
	return 0;
}


unsigned int convert(unsigned int ip)
{
	typedef union {
    int ival;
    char cval[4];
	} Un_t;

	Un_t bb;
	bb.ival=ip;
	unsigned char tmp=bb.cval[0];
	bb.cval[0]=bb.cval[3];
	bb.cval[3]=tmp;
	tmp=bb.cval[1];
	bb.cval[1]=bb.cval[2];
	bb.cval[2]=tmp;

	return bb.ival;
}

int Tracert(char* str_ip,unsigned int max_ttl,unsigned int interval,HWND wnd)
{
	unsigned char count_ttl=1; 
	unsigned char buffer[32];
	long size_reply=sizeof(ICMP_ECHO_REPLY)+sizeof(buffer);
	PICMP_ECHO_REPLY icmp_echo_reply=(PICMP_ECHO_REPLY)malloc(size_reply);
	IP_OPTION_INFORMATION ip_info;
	
	unsigned long ip_adres;
	ip_adres=inet_addr(str_ip);  

	bool reply_b=false;
	bool error_b=false;
	unsigned int mas_time[3];
	mas_time[0]=-1;
	mas_time[1]=-1;
	mas_time[2]=-1;
	unsigned int result_ip=0;

	HANDLE h=IcmpCreateFile();
	if (h==INVALID_HANDLE_VALUE)
	{
		return 1;
	}
	char str_buf[255];
	sprintf(str_buf,"Трассировка маршрута к [%s]",str_ip);
	Add_to_list_box(str_buf,wnd);
	char result_str[255];
	while(result_ip!=ip_adres && count_ttl<max_ttl)
	{
		reply_b=false;
		for (int i=0;i<3;i++)
		{
			ZeroMemory(&ip_info,sizeof(IP_OPTION_INFORMATION));
			ip_info.Ttl=count_ttl;
			ip_info.Tos=0;
			ZeroMemory(icmp_echo_reply,sizeof(ICMP_ECHO_REPLY));
			ZeroMemory(&buffer[0],sizeof(buffer));
			icmp_echo_reply->Data=&buffer[0];
			icmp_echo_reply->DataSize=sizeof(buffer);  
			unsigned long result=IcmpSendEcho(h,ip_adres,&buffer[0],sizeof(buffer),&ip_info,icmp_echo_reply,size_reply,interval);
			
			int c=GetLastError();


			if (result)
			{
				if (icmp_echo_reply->Status==IP_DEST_HOST_UNREACHABLE)
				{
					Add_to_list_box("Данный узел не доступен",wnd);
					error_b=true;
					break;
				}else
					if (icmp_echo_reply->Status==IP_NO_RESOURCES)
					{
						Add_to_list_box("Не хватает ресурсов",wnd);
						error_b=true;
						break;
					}else
						if (icmp_echo_reply->Status==IP_TTL_EXPIRED_TRANSIT || icmp_echo_reply->Status==IP_SUCCESS)
						{
							mas_time[i]=icmp_echo_reply->RoundTripTime;
							result_ip=icmp_echo_reply->Address;
							reply_b=true;
						}else
						{
							Add_to_list_box("Ошибка",wnd);
							error_b=true;
							break;
						}
			}else
			{
				mas_time[i]=-1;
				sprintf(result_str,"Ошибка при отправке!");
			}
			
			if (error_b)
				break;
			
			if (reply_b)
			{
				char tmp1[20],tmp2[20],tmp3[20];
				if (mas_time[0]!=-1)
					sprintf(tmp1," %u ms ",mas_time[0]);
				else
					sprintf(tmp1," * ",mas_time[0]);
				if (mas_time[1]!=-1)
					sprintf(tmp2," %u ms ",mas_time[1]);
				else
					sprintf(tmp2," * ",mas_time[1]);
				if (mas_time[2]!=-1)
					sprintf(tmp3," %u ms ",mas_time[2]);
				else
					sprintf(tmp3," * ",mas_time[2]);

				SOCKADDR_IN ADDR;
				ADDR.sin_addr.s_addr=result_ip;
				char* str=inet_ntoa(ADDR.sin_addr);
				sprintf(result_str,"%ld %s %s %s  IP-адрес: %s",count_ttl,tmp1,tmp2,tmp3,str);
			}else
			{
				char result_str[255];
				sprintf(result_str,"%d Нет ответа",count_ttl);
				break;
			}
		}
		count_ttl++;
		Add_to_list_box(result_str,wnd);
	}
	Add_to_list_box("Трассировка завершена",wnd);
	free(icmp_echo_reply);
	IcmpCloseHandle(h);
	return 0;
}